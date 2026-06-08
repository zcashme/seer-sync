//! Drive the sync engine directly, holding wallet state in memory.
//!
//! `scan()` is the batteries-included path (decode + connect + a `Db`). This sits
//! one layer below: implement [`Account`] over your own store and hand it to
//! `sync::run`. Tracking notes by nullifier makes the balance *net* — it drops
//! when a note is spent — and recovers sends with their recipient. All of this
//! needs a UFVK; a UIVK has no nullifiers, so spends would be invisible.

use std::cell::RefCell;
use std::collections::HashMap;

use seer_sync::sync::chain;
use seer_sync::sync::scan::{Note, Pool, ShieldedNote, Spend};
use seer_sync::sync::{Account, AccountError, Cursor};
use seer_sync::{BlockHeight, Network, ViewKey};

const UFVK: &str = "uview1hzzcqccht7226cqmwfxvesey863wzugkdckl4ecyrpy6pmzteum4x75p8gsqqeghfg0ngkhafvjkgzq6u3d2chf9nxlxqldtpfce80renlet8nw6zvkmkt7v2xqf203t63jufh7640kheemmq89u5gha6w6vvjs93gcae7tcswl9glfjwc80afw86y794cuq0rk8mqyylrguq3wcere2lwv4clhxdc76c79et846p6pv69qw40pxjpu8vywwkg440mp46ed97ytcvumj5lzvqf0n3fv7nfze22me7rh07rtzgr6grh3ra6rq9lgcsstvfh7c70nukklnz7a45eauxj70px6tjquklmh7ayryw205zzp7uuxemm4qd8awxc6vsc0l4dc77v5tg";

const BIRTHDAY: u32 = 3_000_000;

#[derive(Default)]
struct Wallet {
    unspent: RefCell<HashMap<(Pool, [u8; 32]), u64>>,
    sent: RefCell<Vec<(String, u64)>>,
}

impl Account for Wallet {
    fn checkpoint(&self) -> Option<Cursor> {
        None
    }

    fn rewind(&self, _to: BlockHeight) -> Result<(), AccountError> {
        Ok(())
    }

    fn owns_nf(&self, pool: Pool, nf: &[u8; 32]) -> Result<bool, AccountError> {
        Ok(self.unspent.borrow().contains_key(&(pool, *nf)))
    }

    fn apply(&self, _at: Cursor, notes: &[Note], spends: &[Spend]) -> Result<(), AccountError> {
        let mut unspent = self.unspent.borrow_mut();
        for note in notes {
            let value = match &note.note {
                ShieldedNote::Sapling(n) => n.value().inner(),
                ShieldedNote::Orchard(n) => n.value().inner(),
            };
            match (note.is_sent, note.nullifier) {
                (true, _) => {
                    if let Some(addr) = &note.recipient {
                        self.sent.borrow_mut().push((addr.clone(), value));
                    }
                }
                (false, Some(nf)) => {
                    unspent.insert((note.pool(), nf), value);
                }
                _ => {}
            }
        }
        for s in spends {
            unspent.remove(&(s.pool, s.nf));
        }
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = ViewKey::decode(&Network::MainNetwork, UFVK)?;
    let client = chain::connect_auto().await?;
    let wallet = Wallet::default();

    seer_sync::sync::run(client, &key, &Network::MainNetwork, BIRTHDAY, &wallet).await?;

    let unspent = wallet.unspent.borrow();
    let sent = wallet.sent.borrow();
    let balance: u64 = unspent.values().sum();
    println!("unspent balance: {balance} zat across {} note(s)", unspent.len());
    println!("recovered {} send(s):", sent.len());
    for (addr, value) in sent.iter() {
        println!("  {value} zat -> {addr}");
    }
    Ok(())
}
