//! Lightwalletd gRPC client — connect and fetch blocks, transactions, and transparent UTXOs.

use anyhow::{Context, Result};
use futures::{Stream, StreamExt, TryStreamExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, GetAddressUtxosArg, GetAddressUtxosReply, RawTransaction, TxFilter,
};

/// Built-in pool of public mainnet lightwalletd endpoints, tried in order by
/// [`connect_auto`]. `zec.rocks` and its regional mirrors are listed first;
/// the historical ECC endpoint serves as a final fallback. Override by calling
/// [`connect`] with an explicit URL.
pub const DEFAULT_SERVERS: &[&str] = &[
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
    "https://ap.zec.rocks:443",
    "https://mainnet.lightwalletd.com:9067",
];

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

/// Connect to a public mainnet lightwalletd server automatically.
///
/// Tries each endpoint in [`DEFAULT_SERVERS`] in order and returns the first
/// one that connects, so the caller never has to pick a server. Errors from
/// servers that are down are collected and only surfaced if *every* endpoint
/// fails. Pass an explicit URL to [`connect`] to bypass the pool.
pub async fn connect_auto() -> Result<LwdClient> {
    let mut errors = Vec::new();
    for &url in DEFAULT_SERVERS {
        match connect(url).await {
            Ok(client) => return Ok(client),
            Err(e) => errors.push(format!("  {url}: {e:#}")),
        }
    }
    anyhow::bail!(
        "all {} default lightwalletd servers failed:\n{}",
        DEFAULT_SERVERS.len(),
        errors.join("\n")
    )
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

// ─── Block streaming ───────────────────────────────────────────────────────────

/// Default chunk size (Sapling outputs + Orchard actions per batch).
///
/// At ~256 B per output, two chunks in flight peak around 50 MB. Pass an
/// explicit `max_outputs` to [`blocks`] if you need a different memory budget.
pub const DEFAULT_CHUNK_OUTPUTS: usize = 100_000;

/// Stream compact blocks `[from, to]` as memory-bounded chunks.
///
/// The returned [`Stream`] yields `Vec<CompactBlock>` batches, each capped at
/// `max_outputs` Sapling outputs + Orchard actions combined, so peak memory is
/// bounded regardless of range size. A download task runs concurrently and is
/// kept at most one batch ahead of the consumer (channel capacity 1), giving
/// natural back-pressure. Continuity is verified block-to-block and, when
/// `prev_hash` is given (the hash of the block before `from`), across the seam
/// with the caller's stored chain too; a [`Reorg`] or transport failure surfaces
/// as an `Err` item, after which the stream ends.
///
/// This is the crate's single block-fetch primitive. Collect it with
/// [`fetch_range`] and feed the blocks to [`crate::sync::sync`].
///
/// ```no_run
/// # use seer_sync::sync::chain::{connect_auto, blocks, DEFAULT_CHUNK_OUTPUTS};
/// # use futures::StreamExt;
/// # tokio_test::block_on(async {
/// let client = connect_auto().await.unwrap();
/// let mut s = blocks(client, 2_000_000, 2_001_000, DEFAULT_CHUNK_OUTPUTS, None);
/// while let Some(batch) = s.next().await {
///     let batch = batch.unwrap();
///     println!("got {} blocks", batch.len());
/// }
/// # });
/// ```
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

/// Fetch compact blocks `[from, to]` into a single `Vec`.
///
/// Convenience over [`blocks`] for callers that want every block in memory at
/// once (tests, benches, small ranges). For large ranges prefer streaming the
/// chunks directly so memory stays bounded.
pub async fn fetch_range(client: LwdClient, from: u32, to: u32) -> Result<Vec<CompactBlock>> {
    blocks(client, from, to, usize::MAX, None).try_concat().await
}

/// Streamed blocks didn't form a continuous chain — a reorg. Carries the height
/// at which continuity broke, so the caller can walk back and re-sync.
#[derive(thiserror::Error, Debug)]
#[error("chain reorg at height {0}")]
pub struct Reorg(pub u32);

/// The one download loop: drives `GetBlockRange`, groups blocks into
/// `max_outputs`-bounded chunks, verifies `prev_hash`, and forwards each ready
/// chunk over `tx`. Returns early once the consumer drops the receiver.
async fn download(
    mut client: LwdClient,
    from: u32,
    to: u32,
    max_outputs: usize,
    prev_hash: Option<[u8; 32]>,
    tx: &mpsc::Sender<Result<Vec<CompactBlock>>>,
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
    // Seeded with the stored hash of the block before `from`, so the first
    // streamed block is checked against our chain — the seam — and every block
    // after it against its predecessor.
    let mut prev_hash: Option<Vec<u8>> = prev_hash.map(|h| h.to_vec());

    while let Some(block_result) = stream.next().await {
        let block = block_result.context("streaming CompactBlock")?;

        if let Some(ref ph) = prev_hash {
            if !block.prev_hash.is_empty() && &block.prev_hash != ph {
                anyhow::bail!(Reorg(block.height as u32));
            }
        }
        prev_hash = Some(block.hash.clone());

        let block_outputs: usize =
            block.vtx.iter().map(|t| t.outputs.len() + t.actions.len()).sum();

        if output_count + block_outputs > max_outputs && !chunk.is_empty() {
            if tx.send(Ok(std::mem::take(&mut chunk))).await.is_err() {
                return Ok(()); // receiver dropped — consumer cancelled
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

/// Commitment tree frontier returned by the lightwalletd `GetTreeState` RPC.
///
/// The `sapling_tree` and `orchard_tree` strings are hex-encoded frontier
/// serializations compatible with the `incrementalmerkletree` crate.
#[derive(Debug, Clone)]
pub struct LwdTreeState {
    /// Block height this state corresponds to.
    pub height: u32,
    /// Hex-encoded block hash.
    pub hash: String,
    /// Hex-encoded Sapling commitment tree frontier.
    pub sapling_tree: String,
    /// Hex-encoded Orchard commitment tree frontier.
    pub orchard_tree: String,
}

/// Fetch the commitment tree state at a specific block height.
pub async fn get_tree_state(client: &mut LwdClient, height: u32) -> Result<LwdTreeState> {
    let state = client
        .get_tree_state(tonic::Request::new(BlockId { height: height as u64, hash: vec![] }))
        .await
        .context("GetTreeState")?
        .into_inner();

    Ok(LwdTreeState {
        height: state.height as u32,
        hash: state.hash,
        sapling_tree: state.sapling_tree,
        orchard_tree: state.orchard_tree,
    })
}

/// Fetch the commitment tree state at the current chain tip.
pub async fn get_latest_tree_state(client: &mut LwdClient) -> Result<LwdTreeState> {
    let state = client
        .get_latest_tree_state(tonic::Request::new(crate::proto::Empty {}))
        .await
        .context("GetLatestTreeState")?
        .into_inner();

    Ok(LwdTreeState {
        height: state.height as u32,
        hash: state.hash,
        sapling_tree: state.sapling_tree,
        orchard_tree: state.orchard_tree,
    })
}
