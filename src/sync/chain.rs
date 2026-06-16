use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tokio_stream::{Stream, StreamExt};
use tonic::transport::{Channel, ClientTlsConfig};
use zcash_primitives::block::BlockHash;
use zcash_protocol::TxId;

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, RawTransaction, TransparentAddressBlockFilter, TxFilter,
};

pub const DEFAULT_SERVERS: &[&str] = &[
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
    "https://ap.zec.rocks:443",
];

pub type LwdClient = CompactTxStreamerClient<Channel>;

#[derive(thiserror::Error, Debug)]
pub enum ChainError {
    #[error("chain reorg at height {0}")]
    Reorg(u32),
    #[error("lightwalletd RPC: {0}")]
    Rpc(#[from] tonic::Status),
    #[error("connecting to lightwalletd: {0}")]
    Connect(#[from] tonic::transport::Error),
    #[error("invalid lightwalletd url: {0}")]
    Url(#[from] http::uri::InvalidUri),
    #[error("tip height overflowed u32")]
    TipOverflow,
    #[error("all {tried} lightwalletd servers failed:\n{detail}")]
    NoServer { tried: usize, detail: String },
}

pub async fn connect(url: &str) -> Result<LwdClient, ChainError> {
    let uri: http::Uri = url.parse()?;
    let endpoint = Channel::builder(uri)
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?
        .connect()
        .await?;
    Ok(CompactTxStreamerClient::new(endpoint))
}

pub async fn connect_auto() -> Result<LwdClient, ChainError> {
    let mut errors = Vec::new();
    for &url in DEFAULT_SERVERS {
        match connect(url).await {
            Ok(mut client) => match tip_height(&mut client).await {
                Ok(_) => return Ok(client),
                Err(e) => errors.push(format!("  {url}: connected but not serving gRPC: {e}")),
            },
            Err(e) => errors.push(format!("  {url}: {e}")),
        }
    }
    Err(ChainError::NoServer {
        tried: DEFAULT_SERVERS.len(),
        detail: errors.join("\n"),
    })
}

pub async fn tip_height(client: &mut LwdClient) -> Result<u32, ChainError> {
    Ok(tip(client).await?.0)
}

pub async fn tip(client: &mut LwdClient) -> Result<(u32, Option<[u8; 32]>), ChainError> {
    let block = client
        .get_latest_block(tonic::Request::new(ChainSpec {}))
        .await?
        .into_inner();
    let height = u32::try_from(block.height).map_err(|_| ChainError::TipOverflow)?;
    let hash = block.hash[..].try_into().ok();
    Ok((height, hash))
}

pub const DEFAULT_CHUNK_OUTPUTS: usize = 100_000;

pub const DEFAULT_CHUNK_BLOCKS: usize = 1_000;

pub fn blocks(
    client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    prev_hash: Option<BlockHash>,
) -> impl Stream<Item = Result<Vec<CompactBlock>, ChainError>> {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        if let Err(e) = download(client, from, to, max_outputs, prev_hash, &tx).await {
            tx.send(Err(e)).await.ok();
        }
    });
    ReceiverStream::new(rx)
}

async fn download(
    mut client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    prev_hash: Option<BlockHash>,
    tx: &mpsc::Sender<Result<Vec<CompactBlock>, ChainError>>,
) -> Result<(), ChainError> {
    let req = BlockRange {
        start: Some(BlockId {
            height: from as u64,
            hash: vec![],
        }),
        end: Some(BlockId {
            height: to as u64,
            hash: vec![],
        }),
        pool_types: vec![],
    };
    let mut stream = client
        .get_block_range(tonic::Request::new(req))
        .await?
        .into_inner();

    let mut chunk: Vec<CompactBlock> = Vec::new();
    let mut output_count = 0usize;
    let mut prev_hash: Option<Vec<u8>> = prev_hash.map(|h| h.0.to_vec());

    while let Some(block_result) = stream.next().await {
        let block = block_result?;

        if let Some(ref ph) = prev_hash {
            if !block.prev_hash.is_empty() && &block.prev_hash != ph {
                return Err(ChainError::Reorg(block.height as u32));
            }
        }
        prev_hash = Some(block.hash.clone());

        let block_outputs: usize = block
            .vtx
            .iter()
            .map(|t| t.outputs.len() + t.actions.len())
            .sum();

        let chunk_full =
            output_count + block_outputs > max_outputs || chunk.len() >= DEFAULT_CHUNK_BLOCKS;
        if chunk_full && !chunk.is_empty() {
            if tx.send(Ok(std::mem::take(&mut chunk))).await.is_err() {
                return Ok(());
            }
            output_count = 0;
        }

        output_count += block_outputs;
        chunk.push(block);
    }

    if !chunk.is_empty() {
        tx.send(Ok(chunk)).await.ok();
    }
    Ok(())
}

/// Every transaction touching `address` (as recipient or spender) in
/// `[from, to]`, served from the lightwalletd address index.
pub async fn fetch_taddress_transactions(
    client: &mut LwdClient,
    address: String,
    from: u32,
    to: u32,
) -> Result<Vec<RawTransaction>, ChainError> {
    let filter = TransparentAddressBlockFilter {
        address,
        range: Some(BlockRange {
            start: Some(BlockId { height: from as u64, hash: vec![] }),
            end: Some(BlockId { height: to as u64, hash: vec![] }),
            pool_types: vec![],
        }),
    };
    let mut stream = client
        .get_taddress_transactions(tonic::Request::new(filter))
        .await?
        .into_inner();
    let mut out = Vec::new();
    while let Some(tx) = stream.next().await {
        out.push(tx?);
    }
    Ok(out)
}

pub async fn fetch_raw_transaction(
    client: &mut LwdClient,
    txid: &TxId,
) -> Result<RawTransaction, ChainError> {
    let filter = TxFilter {
        block: None,
        index: 0,
        hash: txid.as_ref().to_vec(),
    };
    let raw = client
        .get_transaction(tonic::Request::new(filter))
        .await?
        .into_inner();
    Ok(raw)
}
