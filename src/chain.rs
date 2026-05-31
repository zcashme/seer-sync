//! Lightwalletd gRPC client — connect and fetch compact blocks.

use anyhow::{Context, Result};
use futures::StreamExt;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock,
};

/// The public zec.rocks lightwalletd endpoint.
pub const ZEC_ROCKS: &str = "https://zec.rocks:443";

/// A connected lightwalletd gRPC client.
pub type LwdClient = CompactTxStreamerClient<Channel>;

/// Open a TLS gRPC connection to a lightwalletd instance.
pub async fn connect(url: &str) -> Result<LwdClient> {
    let uri: http::Uri = url.parse().context("parsing LWD url")?;
    let endpoint = Channel::builder(uri)
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?
        .connect()
        .await
        .context("connecting to lightwalletd")?;
    Ok(CompactTxStreamerClient::new(endpoint))
}

/// Return the current chain tip height.
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

/// Fetch compact blocks `[from, to]` inclusive into a `Vec`.
///
/// Blocks are fetched serially in stream order. For large ranges prefer a
/// streaming approach — this buffers the entire range in memory.
pub async fn fetch_range(client: &mut LwdClient, from: u32, to: u32) -> Result<Vec<CompactBlock>> {
    let req = BlockRange {
        start: Some(BlockId { height: from as u64, hash: vec![] }),
        end: Some(BlockId { height: to as u64, hash: vec![] }),
        pool_types: vec![],
    };
    let mut stream = client
        .get_block_range(tonic::Request::new(req))
        .await
        .context("GetBlockRange")?
        .into_inner();

    let mut blocks = Vec::new();
    while let Some(block) = stream.next().await {
        blocks.push(block.context("streaming CompactBlock")?);
    }
    Ok(blocks)
}
