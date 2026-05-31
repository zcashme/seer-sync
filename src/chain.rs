//! Lightwalletd gRPC client — connect and fetch blocks, transactions, and transparent UTXOs.

use anyhow::{Context, Result};
use futures::StreamExt;
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

/// Fetch compact blocks `[from, to]` inclusive into a `Vec`.
///
/// All blocks are buffered in memory. For ranges exceeding ~50 000 blocks,
/// prefer [`stream_blocks`] to avoid large allocations.
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
