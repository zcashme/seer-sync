use std::time::Duration;

use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, NetworkType, Parameters};
use zcash_protocol::TxId;

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, GetAddressUtxosArg, GetAddressUtxosReply, RawTransaction,
    TransparentAddressBlockFilter, TxFilter,
};

const MAINNET_SERVERS: &[&str] = &[
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
    "https://ap.zec.rocks:443",
];
const TESTNET_SERVERS: &[&str] = &["https://testnet.zec.rocks:443"];

/// How long one bundled server may take to connect and serve its tip.
/// A stall moves on to the next server instead of holding the caller there.
const SERVER_ATTEMPT: Duration = Duration::from_secs(30);

/// Bundled servers for `network`. Regtest has none.
fn servers(network: NetworkType) -> &'static [&'static str] {
    match network {
        NetworkType::Main => MAINNET_SERVERS,
        NetworkType::Test => TESTNET_SERVERS,
        NetworkType::Regtest => &[],
    }
}

#[derive(Clone)]
pub struct LwdClient {
    inner: CompactTxStreamerClient<Channel>,
}

#[derive(thiserror::Error, Debug)]
pub enum RpcError {
    #[error("lightwalletd RPC failed: {0}")]
    Status(#[from] tonic::Status),
    #[error("invalid lightwalletd response: {0}")]
    InvalidResponse(String),
}

#[derive(thiserror::Error, Debug)]
#[error("no bundled lightwalletd server is available")]
pub struct NoServer;

fn parse_block_hash(bytes: &[u8], method: &str) -> Result<BlockHash, RpcError> {
    BlockHash::try_from_slice(bytes).ok_or_else(|| {
        RpcError::InvalidResponse(format!(
            "{method}: expected a 32-byte block hash, received {} bytes",
            bytes.len()
        ))
    })
}

fn parse_block_id(block: BlockId) -> Result<(BlockHeight, BlockHash), RpcError> {
    let height = BlockHeight::try_from(block.height).map_err(|_| {
        RpcError::InvalidResponse(format!(
            "GetLatestBlock: height {} exceeds u32",
            block.height
        ))
    })?;
    let hash = parse_block_hash(&block.hash, "GetLatestBlock")?;
    Ok((height, hash))
}

/// Connect to the first bundled server for `params.network_type()` that
/// serves its tip within `SERVER_ATTEMPT`; a stall tries the next server.
pub async fn connect_auto<P: Parameters>(params: &P) -> Result<LwdClient, NoServer> {
    for &url in servers(params.network_type()) {
        let probe = async {
            let mut client = LwdClient::connect(url).await.ok()?;
            client.latest_block().await.ok()?;
            Some(client)
        };
        if let Ok(Some(client)) = tokio::time::timeout(SERVER_ATTEMPT, probe).await {
            return Ok(client);
        }
    }

    Err(NoServer)
}

impl LwdClient {
    async fn connect(url: &'static str) -> Result<Self, tonic::transport::Error> {
        let uri = url
            .parse::<http::Uri>()
            .expect("bundled lightwalletd URLs are valid HTTP URIs");
        let channel = Channel::builder(uri)
            .tls_config(ClientTlsConfig::new().with_webpki_roots())?
            .connect()
            .await?;

        Ok(Self {
            inner: CompactTxStreamerClient::new(channel),
        })
    }

    pub async fn latest_block(&mut self) -> Result<(BlockHeight, BlockHash), RpcError> {
        let block = self
            .inner
            .get_latest_block(tonic::Request::new(ChainSpec {}))
            .await?
            .into_inner();

        parse_block_id(block)
    }

    pub(crate) async fn block_hash(&mut self, height: BlockHeight) -> Result<BlockHash, RpcError> {
        let block = self
            .inner
            .get_block(tonic::Request::new(BlockId {
                height: u64::from(u32::from(height)),
                hash: Vec::new(),
            }))
            .await?
            .into_inner();

        parse_block_hash(&block.hash, "GetBlock")
    }

    pub(crate) async fn blocks(
        &mut self,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<impl Stream<Item = Result<CompactBlock, RpcError>>, RpcError> {
        let stream = self
            .inner
            .get_block_range(tonic::Request::new(BlockRange {
                start: Some(BlockId {
                    height: u64::from(u32::from(from)),
                    hash: Vec::new(),
                }),
                end: Some(BlockId {
                    height: u64::from(u32::from(to)),
                    hash: Vec::new(),
                }),
                pool_types: Vec::new(),
            }))
            .await?
            .into_inner();

        Ok(stream.map(|result| result.map_err(RpcError::from)))
    }

    pub(crate) async fn raw_transaction(
        &mut self,
        txid: &TxId,
    ) -> Result<RawTransaction, RpcError> {
        Ok(self
            .inner
            .get_transaction(tonic::Request::new(TxFilter {
                block: None,
                index: 0,
                hash: txid.as_ref().to_vec(),
            }))
            .await?
            .into_inner())
    }

    pub async fn taddress_transactions(
        &mut self,
        address: &str,
        from: BlockHeight,
        to: BlockHeight,
    ) -> Result<Vec<RawTransaction>, RpcError> {
        let mut stream = self
            .inner
            .get_taddress_transactions(tonic::Request::new(TransparentAddressBlockFilter {
                address: address.to_owned(),
                range: Some(BlockRange {
                    start: Some(BlockId {
                        height: u64::from(u32::from(from)),
                        hash: Vec::new(),
                    }),
                    end: Some(BlockId {
                        height: u64::from(u32::from(to)),
                        hash: Vec::new(),
                    }),
                    pool_types: Vec::new(),
                }),
            }))
            .await?
            .into_inner();
        let mut transactions = Vec::new();

        while let Some(transaction) = stream.next().await {
            transactions.push(transaction?);
        }

        Ok(transactions)
    }

    /// Fetches the full serialized transaction for every provided txid in parallel.
    pub(crate) async fn fetch_raw_transactions(
        &mut self,
        txids: &[(TxId, BlockHeight)],
    ) -> Result<Vec<(TxId, BlockHeight, RawTransaction)>, RpcError> {
        let mut handles = Vec::with_capacity(txids.len());
        for &(txid, height) in txids {
            let mut client = self.clone();
            handles.push(tokio::spawn(async move {
                client
                    .raw_transaction(&txid)
                    .await
                    .map(|raw| (txid, height, raw))
            }));
        }

        let mut results = Vec::with_capacity(handles.len());
        for handle in handles {
            let result = handle.await.expect("fetch task panicked")?;
            results.push(result);
        }

        Ok(results)
    }

    /// Returns unspent transparent outputs for the given addresses at or above
    /// `start_height`.
    #[allow(dead_code)] // gRPC wrapper kept for transparent-history consumers
    pub(crate) async fn address_utxos(
        &mut self,
        addresses: &[String],
        start_height: BlockHeight,
    ) -> Result<Vec<GetAddressUtxosReply>, RpcError> {
        let reply = self
            .inner
            .get_address_utxos(tonic::Request::new(GetAddressUtxosArg {
                addresses: addresses.to_vec(),
                start_height: u64::from(u32::from(start_height)),
                max_entries: 0,
            }))
            .await?
            .into_inner();

        Ok(reply.address_utxos)
    }
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::{MainNetwork, NetworkUpgrade};

    use super::*;

    #[test]
    fn block_id_rejects_malformed_fields_without_panicking() {
        let height = u64::from(u32::MAX) + 1;
        let error = parse_block_id(BlockId {
            height,
            hash: vec![0; 32],
        })
        .unwrap_err();
        assert!(matches!(error, RpcError::InvalidResponse(_)));
        assert!(error.to_string().contains(&height.to_string()));

        for len in [0, 31, 33] {
            let error = parse_block_id(BlockId {
                height: 42,
                hash: vec![0; len],
            })
            .unwrap_err();
            assert!(matches!(error, RpcError::InvalidResponse(_)));
            assert!(error.to_string().contains("GetLatestBlock"));
            assert!(error.to_string().contains(&format!("received {len} bytes")));

            let error = parse_block_hash(&vec![0; len], "GetBlock").unwrap_err();
            assert!(matches!(error, RpcError::InvalidResponse(_)));
            assert!(error.to_string().contains("GetBlock"));
        }
    }

    #[test]
    fn block_id_preserves_valid_fields() {
        let height = u32::MAX;
        let hash = [7; 32];
        assert_eq!(
            parse_block_id(BlockId {
                height: u64::from(height),
                hash: hash.to_vec()
            })
            .unwrap(),
            (BlockHeight::from_u32(height), BlockHash(hash)),
        );
    }

    #[test]
    fn rpc_status_preserves_code_message_and_metadata() {
        let mut status = tonic::Status::unavailable("server restarting");
        status
            .metadata_mut()
            .insert("retry-after", "30".parse().unwrap());
        let error = RpcError::from(status);
        let RpcError::Status(status) = error else {
            panic!("expected RPC status")
        };
        assert_eq!(status.code(), tonic::Code::Unavailable);
        assert_eq!(status.message(), "server restarting");
        assert_eq!(status.metadata().get("retry-after").unwrap(), "30");
    }

    /// Live: needs network access to the bundled mainnet servers.
    /// Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore = "live mainnet"]
    async fn connect_auto_reaches_a_mainnet_tip() {
        let mut client = connect_auto(&MainNetwork).await.unwrap();
        let (tip, _) = client.latest_block().await.unwrap();
        let nu5 = MainNetwork.activation_height(NetworkUpgrade::Nu5).unwrap();
        assert!(tip > nu5, "mainnet tip {tip} is past NU5");
    }
}
