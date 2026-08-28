//! Test script for `GetTaddressTransactions`.
//!
//! Fetches every transaction involving the given transparent address in the
//! requested block range and prints its height and txid.
//!
//! Usage:
//!     cargo run --release --example taddr_txs -- <t-address> <start-height> <end-height>
//!
//! Example:
//!     cargo run --release --example taddr_txs -- t1YOURADDRESS 3000000 3010000

use seer_sync::{BlockHeight, Network};
use seer_sync::sync::chain::LwdClient;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::BranchId;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: taddr_txs <t-address> <start-height> <end-height>";
    let address = args.next().expect(usage);
    let start: u32 = args.next().expect(usage).parse()?;
    let end: u32 = args.next().expect(usage).parse()?;

    let network = Network::MainNetwork;

    println!("connecting to a mainnet lightwalletd server...");
    let mut client = LwdClient::connect_auto(network).await?;

    println!(
        "querying {} for transactions in heights {}..{}",
        address, start, end
    );
    let raw_txs = client
        .taddress_transactions(
            &address,
            BlockHeight::from_u32(start),
            BlockHeight::from_u32(end),
        )
        .await?;

    println!("server returned {} raw transaction(s)", raw_txs.len());

    for raw in raw_txs {
        let height_u64 = raw.height;
        if height_u64 == 0 {
            println!(
                "  [mempool/unmined, {} bytes] (skipping txid parse)",
                raw.data.len()
            );
            continue;
        }
        let height = u32::try_from(height_u64)?;
        let branch_id = BranchId::for_height(&network, BlockHeight::from_u32(height));
        let tx = Transaction::read(&raw.data[..], branch_id)?;
        let txid = tx.txid();
        println!("  height={} txid={}", height, hex_bytes(txid.as_ref()));
    }

    Ok(())
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
