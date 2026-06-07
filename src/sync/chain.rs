use anyhow::{Context, Result};
use futures::{Stream, StreamExt, TryStreamExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, RawTransaction, TxFilter,
};

pub const DEFAULT_SERVERS: &[&str] = &[
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
    "https://ap.zec.rocks:443",
];

pub type LwdClient = CompactTxStreamerClient<Channel>;

pub async fn connect(url: &str) -> Result<LwdClient> {
    let uri: http::Uri = url.parse().context("parsing LWD url")?;
    let endpoint = Channel::builder(uri)
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?
        .connect()
        .await
        .context("connecting to lightwalletd")?;
    Ok(CompactTxStreamerClient::new(endpoint))
}

/// Broadcast a raw serialized transaction to the connected lightwalletd node.
///
/// Calls the `SendTransaction` RPC with `height = 0` (mempool submission).
/// Returns an error if the node rejects the transaction (`errorCode != 0`).
pub async fn broadcast_transaction(client: &mut LwdClient, raw_tx: Vec<u8>) -> Result<()> {
    let resp = client
        .send_transaction(tonic::Request::new(RawTransaction {
            data: raw_tx,
            height: 0,
        }))
        .await
        .context("SendTransaction RPC")?
        .into_inner();

    if resp.error_code != 0 {
        anyhow::bail!(
            "SendTransaction rejected (code {}): {}",
            resp.error_code,
            resp.error_message
        );
    }
    Ok(())
}

pub async fn connect_auto() -> Result<LwdClient> {
    let mut errors = Vec::new();
    for &url in DEFAULT_SERVERS {
        match connect(url).await {
            Ok(mut client) => match tip_height(&mut client).await {
                Ok(_) => return Ok(client),
                Err(e) => errors.push(format!("  {url}: connected but not serving gRPC: {e:#}")),
            },
            Err(e) => errors.push(format!("  {url}: {e:#}")),
        }
    }
    anyhow::bail!(
        "all {} default lightwalletd servers failed:\n{}",
        DEFAULT_SERVERS.len(),
        errors.join("\n")
    )
}

pub async fn tip_height(client: &mut LwdClient) -> Result<u32> {
    u32::try_from(
        client
            .get_latest_block(tonic::Request::new(ChainSpec {}))
            .await
            .context("GetLatestBlock")?
            .into_inner()
            .height,
    )
    .context("tip height overflowed u32")
}

pub const DEFAULT_CHUNK_OUTPUTS: usize = 100_000;

pub const DEFAULT_CHUNK_BLOCKS: usize = 1_000;

pub fn blocks(
    client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    prev_hash: Option<[u8; 32]>,
) -> impl Stream<Item = Result<Vec<CompactBlock>>> {
    let (tx, rx) = mpsc::channel(1);
    tokio::spawn(async move {
        if let Err(e) = download(client, from, to, max_outputs, prev_hash, &tx).await {
            tx.send(Err(e)).await.ok();
        }
    });
    ReceiverStream::new(rx)
}

pub async fn fetch_range(client: LwdClient, from: u32, to: u32) -> Result<Vec<CompactBlock>> {
    blocks(client, from, to, usize::MAX, None)
        .try_concat()
        .await
}

#[derive(thiserror::Error, Debug)]
#[error("chain reorg at height {0}")]
pub struct Reorg(pub u32);

async fn download(
    mut client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    prev_hash: Option<[u8; 32]>,
    tx: &mpsc::Sender<Result<Vec<CompactBlock>>>,
) -> Result<()> {
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
        .await
        .context("GetBlockRange")?
        .into_inner();

    let mut chunk: Vec<CompactBlock> = Vec::new();
    let mut output_count = 0usize;
    let mut prev_hash: Option<Vec<u8>> = prev_hash.map(|h| h.to_vec());

    while let Some(block_result) = stream.next().await {
        let block = block_result.context("streaming CompactBlock")?;

        if let Some(ref ph) = prev_hash {
            if !block.prev_hash.is_empty() && &block.prev_hash != ph {
                anyhow::bail!(Reorg(block.height as u32));
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

pub async fn fetch_raw_transaction(
    client: &mut LwdClient,
    txid: &[u8; 32],
) -> Result<RawTransaction> {
    let filter = TxFilter {
        block: None,
        index: 0,
        hash: txid.to_vec(),
    };
    let raw = client
        .get_transaction(tonic::Request::new(filter))
        .await
        .context("GetTransaction")?
        .into_inner();
    Ok(raw)
}
