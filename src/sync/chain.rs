
use anyhow::{Context, Result};
use futures::{Stream, StreamExt, TryStreamExt};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig};

use crate::proto::{
    compact_tx_streamer_client::CompactTxStreamerClient, BlockId, BlockRange, ChainSpec,
    CompactBlock, GetAddressUtxosArg, GetAddressUtxosReply, RawTransaction, TxFilter,
};

pub const DEFAULT_SERVERS: &[&str] = &[
    "https://zec.rocks:443",
    "https://na.zec.rocks:443",
    "https://eu.zec.rocks:443",
    "https://ap.zec.rocks:443",
    "https://mainnet.lightwalletd.com:9067",
];

pub type LwdClient = CompactTxStreamerClient<Channel>;

#[derive(Debug, Clone)]
pub struct TransparentUtxo {
    pub address: String,
    pub txid: [u8; 32],
    pub index: u32,
    pub script: Vec<u8>,
    pub value_zat: u64,
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

pub async fn connect(url: &str) -> Result<LwdClient> {
    let uri: http::Uri = url.parse().context("parsing LWD url")?;
    let endpoint = Channel::builder(uri)
        .tls_config(ClientTlsConfig::new().with_webpki_roots())?
        .connect()
        .await
        .context("connecting to lightwalletd")?;
    Ok(CompactTxStreamerClient::new(endpoint))
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

/// Cap chunks by block count too. Output-based chunking alone is pathological in
/// sparse regions: near height 3M density is ~1 output/block, so a 100k-output
/// chunk spans ~95k blocks — and progress + the cursor checkpoint only advance
/// per chunk. Capping blocks keeps both regular regardless of density.
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
    blocks(client, from, to, usize::MAX, None).try_concat().await
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

        let chunk_full = output_count + block_outputs > max_outputs
            || chunk.len() >= DEFAULT_CHUNK_BLOCKS;
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

pub async fn fetch_transparent_utxos(
    client: &mut LwdClient,
    addresses: &[String],
    start_height: u32,
) -> Result<Vec<TransparentUtxo>> {
    let req = GetAddressUtxosArg {
        addresses: addresses.to_vec(),
        start_height: start_height as u64,
        max_entries: 0,
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
