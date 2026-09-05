use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_primitives::block::BlockHash;
use zcash_protocol::consensus::{BlockHeight, Network};
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

fn servers(network: Network) -> &'static [&'static str] {
    match network {
        Network::MainNetwork => MAINNET_SERVERS,
        Network::TestNetwork => TESTNET_SERVERS,
    }
}

#[derive(Clone)]
pub struct LwdClient {
    inner: CompactTxStreamerClient<Channel>,
}

#[derive(thiserror::Error, Debug)]
#[error("lightwalletd RPC {code}: {message}")]
pub struct RpcError {
    pub code: String,
    pub message: String,
}

#[derive(thiserror::Error, Debug)]
#[error("no bundled lightwalletd server is available")]
pub struct NoServer;

impl From<tonic::Status> for RpcError {
    fn from(status: tonic::Status) -> Self {
        Self {
            code: format!("{:?}", status.code()),
            message: status.message().to_owned(),
        }
    }
}

impl LwdClient {
    pub async fn connect_auto(network: Network) -> Result<Self, NoServer> {
        for &url in servers(network) {
            if let Ok(mut client) = Self::connect(url).await {
                if client.latest_block().await.is_ok() {
                    return Ok(client);
                }
            }
        }

        Err(NoServer)
    }

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

        Ok((
            BlockHeight::from_u32(
                u32::try_from(block.height)
                    .expect("lightwalletd block heights fit Zcash's block-height type"),
            ),
            BlockHash(
                block
                    .hash
                    .as_slice()
                    .try_into()
                    .expect("lightwalletd block hashes are 32 bytes"),
            ),
        ))
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

    /// Returns true if `prev_hash` does not connect to the last trusted block.
    pub(crate) fn detect_reorg(
        &self,
        prior: Option<(BlockHeight, BlockHash)>,
        prev_hash: BlockHash,
    ) -> Option<BlockHeight> {
        if let Some((height, hash)) = prior {
            if prev_hash != hash {
                return Some(height);
            }
        }
        None
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
