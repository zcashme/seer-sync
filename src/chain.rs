//! Lightwalletd gRPC client — connect and fetch blocks, transactions, and transparent UTXOs.

use anyhow::{Context, Result};
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, GetAddressUtxosArg, GetAddressUtxosReply, RawTransaction, TxFilter,
};

/// The public zec.rocks lightwalletd endpoint.
pub const ZEC_ROCKS: &str = "https://zec.rocks:443";

/// A connected lightwalletd gRPC client.
pub type LwdClient = CompactTxStreamerClient<Channel>;

/// A transparent UTXO fetched from the lightwalletd server.
#[derive(Debug, Clone)]
pub struct TransparentUtxo {
    /// Base58Check-encoded transparent address.
    pub address: String,
    /// Transaction ID (32 bytes, protocol byte order).
    pub txid: [u8; 32],
    /// Output index within the transaction.
    pub index: u32,
    /// Raw locking script.
    pub script: Vec<u8>,
    /// Value in zatoshis.
    pub value_zat: u64,
    /// Block height where this UTXO was created.
    pub height: u32,
}

impl TryFrom<GetAddressUtxosReply> for TransparentUtxo {
    type Error = anyhow::Error;

    fn try_from(r: GetAddressUtxosReply) -> Result<Self> {
        let txid: [u8; 32] = r.txid.try_into().map_err(|_| anyhow::anyhow!("txid not 32 bytes"))?;
        Ok(Self {
            address: r.address,
            txid,
            index: r.index as u32,
            script: r.script,
            value_zat: r.value_zat as u64,
            height: r.height as u32,
        })
    }
}

// ─── Connection ──────────────────────────────────────────────────────────────

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

// ─── Chain tip ───────────────────────────────────────────────────────────────

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

// ─── Block fetching ───────────────────────────────────────────────────────────

/// Hard cap on outputs per chunk regardless of available RAM.
pub const MAX_OUTPUTS_PER_CHUNK: usize = 200_000;

/// Return the current available system memory in bytes.
pub fn get_available_memory() -> usize {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    sys.available_memory() as usize
}

/// Conservative in-memory cost per compact output or action (bytes).
///
/// Nullifier (32) + cmx/cmu (32) + epk (32) + compact ciphertext (52) plus
/// proto framing rounds to ~256 bytes.
pub const fn get_mem_per_output() -> usize {
    256
}

/// Compute a chunk size (in total shielded outputs) that fits in available RAM.
///
/// Uses at most half of available memory and never exceeds
/// [`MAX_OUTPUTS_PER_CHUNK`], adapting to the machine at runtime.
pub fn adaptive_chunk_size() -> usize {
    let from_ram = (get_available_memory() / 2) / get_mem_per_output();
    from_ram.min(MAX_OUTPUTS_PER_CHUNK).max(1_000)
}

/// Fetch compact blocks `[from, to]` inclusive into a single `Vec`.
///
/// All blocks are buffered in memory at once. For large ranges prefer
/// [`fetch_blocks_adaptive`] which breaks the download into RAM-bounded chunks.
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

/// Stream compact blocks `[from, to]` in memory-bounded chunks.
///
/// Each chunk is limited to `max_outputs` Sapling outputs + Orchard actions
/// combined, so memory usage is bounded even over very large ranges.
/// Blocks within a chunk are already in height order.
///
/// A `ChainError::Reorg` is returned if `prev_hash` verification fails.
pub async fn fetch_blocks_chunked(
    client: &mut LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
) -> Result<Vec<Vec<CompactBlock>>> {
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

    let mut chunks: Vec<Vec<CompactBlock>> = Vec::new();
    let mut chunk: Vec<CompactBlock> = Vec::new();
    let mut output_count = 0usize;
    let mut prev_hash: Option<Vec<u8>> = None;

    while let Some(block_result) = stream.next().await {
        let block = block_result.context("streaming CompactBlock")?;

        // Reorg detection.
        if let Some(ref ph) = prev_hash {
            if !block.prev_hash.is_empty() && &block.prev_hash != ph {
                anyhow::bail!(
                    "chain reorganization at height {}",
                    block.height
                );
            }
        }
        prev_hash = Some(block.hash.clone());

        let block_outputs: usize = block
            .vtx
            .iter()
            .map(|tx| tx.outputs.len() + tx.actions.len())
            .sum();

        if output_count + block_outputs > max_outputs && !chunk.is_empty() {
            chunks.push(std::mem::take(&mut chunk));
            output_count = 0;
        }

        output_count += block_outputs;
        chunk.push(block);
    }
    if !chunk.is_empty() {
        chunks.push(chunk);
    }
    Ok(chunks)
}

/// Stream compact blocks `[from, to]` using a chunk size derived from
/// [`adaptive_chunk_size`].
///
/// Equivalent to `fetch_blocks_chunked(client, from, to, adaptive_chunk_size())`
/// but selects the chunk size automatically based on available system RAM.
pub async fn fetch_blocks_adaptive(
    client: &mut LwdClient,
    from: u32,
    to: u32,
) -> Result<Vec<Vec<CompactBlock>>> {
    fetch_blocks_chunked(client, from, to, adaptive_chunk_size()).await
}

/// Streaming block-download worker — runs inside a spawned task.
///
/// Fetches compact blocks `[from, to]` from `client`, groups them into
/// output-bounded batches (`max_outputs`), and sends each batch over `tx`.
/// A channel capacity of 1 at the call site gives natural back-pressure:
/// the downloader fetches at most one batch ahead of the consumer.
///
/// ```no_run
/// # use seer_sync::chain::{connect, download_chain, adaptive_chunk_size, ZEC_ROCKS};
/// # tokio_test::block_on(async {
/// let client = connect(ZEC_ROCKS).await.unwrap();
/// let (tx, mut rx) = tokio::sync::mpsc::channel(1);
/// let downloader = tokio::spawn(async move {
///     download_chain(client, 2_000_000, 2_001_000, adaptive_chunk_size(), tx).await
/// });
/// while let Some(blocks) = rx.recv().await {
///     // scan this batch while the downloader prefetches the next
///     println!("got {} blocks", blocks.len());
/// }
/// downloader.await.unwrap().unwrap();
/// # });
/// ```
pub async fn download_chain(
    mut client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    tx: mpsc::Sender<Vec<CompactBlock>>,
) -> Result<()> {
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

    let mut chunk: Vec<CompactBlock> = Vec::new();
    let mut output_count = 0usize;
    let mut prev_hash: Option<Vec<u8>> = None;

    while let Some(block_result) = stream.next().await {
        let block = block_result.context("streaming CompactBlock")?;

        if let Some(ref ph) = prev_hash {
            if !block.prev_hash.is_empty() && &block.prev_hash != ph {
                anyhow::bail!("chain reorganization at height {}", block.height);
            }
        }
        prev_hash = Some(block.hash.clone());

        let block_outputs: usize =
            block.vtx.iter().map(|t| t.outputs.len() + t.actions.len()).sum();

        if output_count + block_outputs > max_outputs && !chunk.is_empty() {
            if tx.send(std::mem::take(&mut chunk)).await.is_err() {
                return Ok(()); // receiver dropped — consumer cancelled
            }
            output_count = 0;
        }

        output_count += block_outputs;
        chunk.push(block);
    }

    if !chunk.is_empty() {
        tx.send(chunk).await.ok();
    }
    Ok(())
}

/// Spawn a download worker and return its join handle and block-batch receiver.
///
/// The channel has capacity 1, so the downloader prefetches at most one batch
/// ahead of the consumer. Use [`adaptive_chunk_size`] for `max_outputs` unless
/// you have a specific memory budget.
pub fn stream_blocks(
    client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
) -> (JoinHandle<Result<()>>, mpsc::Receiver<Vec<CompactBlock>>) {
    let (tx, rx) = mpsc::channel(1);
    let handle = tokio::spawn(download_chain(client, from, to, max_outputs, tx));
    (handle, rx)
}

// ─── Full transaction fetch ───────────────────────────────────────────────────

/// Fetch the raw bytes of a transaction by its ID.
///
/// Returns the serialized transaction and the block height it was mined in.
/// The transaction can be parsed with `zcash_primitives::transaction::Transaction::read`
/// for full note decryption and memo recovery.
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

// ─── Transparent UTXOs ────────────────────────────────────────────────────────

/// Fetch all transparent UTXOs for a list of t-addresses since `start_height`.
///
/// Uses the `GetAddressUtxos` RPC which returns all unspent UTXOs. The result
/// is sorted by height ascending.
pub async fn fetch_transparent_utxos(
    client: &mut LwdClient,
    addresses: &[String],
    start_height: u32,
) -> Result<Vec<TransparentUtxo>> {
    let req = GetAddressUtxosArg {
        addresses: addresses.to_vec(),
        start_height: start_height as u64,
        max_entries: 0, // 0 = unlimited
    };
    let reply = client
        .get_address_utxos(tonic::Request::new(req))
        .await
        .context("GetAddressUtxos")?
        .into_inner();

    reply
        .address_utxos
        .into_iter()
        .map(TransparentUtxo::try_from)
        .collect()
}

/// Stream transparent UTXOs for `addresses` starting at `start_height`.
///
/// Uses the `GetAddressUtxosStream` RPC for large result sets.
pub async fn stream_transparent_utxos(
    client: &mut LwdClient,
    addresses: Vec<String>,
    start_height: u32,
) -> Result<Vec<TransparentUtxo>> {
    let req = GetAddressUtxosArg {
        addresses,
        start_height: start_height as u64,
        max_entries: 0,
    };
    let mut stream = client
        .get_address_utxos_stream(tonic::Request::new(req))
        .await
        .context("GetAddressUtxosStream")?
        .into_inner();

    let mut utxos = Vec::new();
    while let Some(item) = stream.next().await {
        let r = item.context("streaming UTXO")?;
        if let Ok(utxo) = TransparentUtxo::try_from(r) {
            utxos.push(utxo);
        }
    }
    Ok(utxos)
}
