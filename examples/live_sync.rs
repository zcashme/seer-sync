//! No-db example: drive the raw `sync::run` engine yourself.
//!
//! `seer_sync::scan()` is the batteries-included path (connect + decode + a Db).
//! Here we sit one layer below and supply the four callbacks ourselves, holding
//! all wallet state in memory:
//!
//!   resume_point  where to start (or resume after a reorg)
//!   rewind        called on a reorg; drop in-memory state above that height
//!   owns_nf       did we receive a note with this nullifier in an earlier
//!                 batch? (spends within the current batch are matched by the
//!                 engine itself) — answering this is what makes the sync
//!                 spend-aware
//!   sink          per batch: the notes found, and the spends of our own notes
//!
//! Because we track our notes by nullifier, the balance is *net*: it drops when
//! a note is spent. Sends are recovered with their recipient, including sends
//! that leave no change. All of this needs a UFVK; a UIVK cannot derive
//! nullifiers, so `owns_nf` would always be false and spends invisible.

use std::cell::RefCell;
use std::collections::HashMap;

use anyhow::{anyhow, Result};
use seer_sync::sync::chain;
use seer_sync::sync::scan::{Pool, ShieldedNote};
use seer_sync::{BlockHeight, Network, ViewKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

/// Minimal in-memory wallet: the unspent notes we own (keyed by nullifier, so a
/// later spend can drop them) and the sends we've recovered via the OVK.
#[derive(Default)]
struct Wallet {
    unspent: HashMap<(Pool, [u8; 32]), u64>,
    sent: Vec<(String, u64)>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // sync::run takes a client; seer_sync::scan() calls connect_auto internally.
    // Here we're below that layer, so we do it ourselves.
    let key = ViewKey::decode(&Network::MainNetwork, UFVK).map_err(|e| anyhow!(e))?;
    let client = chain::connect_auto().await?;
    let wallet = RefCell::new(Wallet::default());

    seer_sync::sync::run(
        client,
        &key,
        &Network::MainNetwork,
        || (BlockHeight::from_u32(BIRTHDAY), None), // no persisted resume point
        |_| Ok(()),                                  // nothing to rewind in memory
        |pool, nf| Ok(wallet.borrow().unspent.contains_key(&(pool, *nf))),
        |_height, _hash, notes, spends| {
            let mut w = wallet.borrow_mut();
            for note in notes {
                let value = match &note.note {
                    ShieldedNote::Sapling(n) => n.value().inner(),
                    ShieldedNote::Orchard(n) => n.value().inner(),
                };
                match (note.is_sent, note.nullifier) {
                    // An output we sent, recovered via the OVK.
                    (true, _) => {
                        if let Some(addr) = &note.recipient {
                            w.sent.push((addr.clone(), value));
                        }
                    }
                    // A note we received whose spend we can later recognize.
                    (false, Some(nf)) => {
                        w.unspent.insert((note.pool(), nf), value);
                    }
                    _ => {}
                }
            }
            // Drop notes we've now watched get spent.
            for s in spends {
                w.unspent.remove(&(s.pool, s.nf));
            }
            Ok(())
        },
    )
    .await?;

    let w = wallet.borrow();
    let balance: u64 = w.unspent.values().sum();
    println!("unspent balance: {balance} zat across {} note(s)", w.unspent.len());
    println!("recovered {} send(s):", w.sent.len());
    for (addr, value) in &w.sent {
        println!("  {value} zat -> {addr}");
    }
    Ok(())
}
