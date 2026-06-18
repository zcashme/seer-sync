//! Bring your own store: a minimal in-memory `Account` driven by `run`.
//!
//!     cargo run --release --example custom_account -- <UFVK> <BIRTHDAY>

use std::sync::Mutex;

use seer_sync::{
    chain, run, Account, AccountError, Batch, BlockHeight, Cursor, Network, Nullifier, Pool,
    Resume, ShieldedNote, ViewKey,
};

struct Memory {
    birthday: BlockHeight,
    state: Mutex<State>,
}

#[derive(Default)]
struct State {
    checkpoint: Option<Cursor>,
    unspent: Vec<(Pool, Nullifier, u64, BlockHeight)>,
}

impl Account for Memory {
    fn resume(&self) -> Result<Resume, AccountError> {
        let s = self.state.lock().unwrap();
        Ok(Resume {
            birthday: self.birthday,
            checkpoint: s.checkpoint,
            nullifiers: s.unspent.iter().map(|(p, nf, ..)| (*p, *nf)).collect(),
            outpoints: Vec::new(),
        })
    }

    fn rewind(&self, to: BlockHeight) -> Result<(), AccountError> {
        let mut s = self.state.lock().unwrap();
        s.unspent.retain(|(.., height)| *height <= to);
        s.checkpoint = Some(Cursor {
            height: to,
            hash: None,
        });
        Ok(())
    }

    fn apply(&self, at: Cursor, batch: &Batch) -> Result<(), AccountError> {
        let mut s = self.state.lock().unwrap();
        for note in &batch.notes {
            let value = match &note.note {
                ShieldedNote::Orchard(n) => n.value().inner(),
                ShieldedNote::Sapling(n) => n.value().inner(),
            };
            if note.is_sent {
                println!("sent {value} zat in {} at {}", note.txid, note.height);
            } else {
                println!("received {value} zat in {} at {}", note.txid, note.height);
                if let Some(nf) = note.nullifier {
                    s.unspent.push((note.pool(), nf, value, note.height));
                }
            }
        }
        for spend in &batch.spends {
            s.unspent.retain(|(_, nf, ..)| *nf != spend.nf);
            println!("spent a note in {} at {}", spend.txid, spend.height);
        }
        s.checkpoint = Some(at);
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: custom_account <ufvk> <birthday-height>";
    let key = ViewKey::decode(&Network::MainNetwork, &args.next().expect(usage))?;
    let birthday: u32 = args.next().expect(usage).parse()?;

    let account = Memory {
        birthday: BlockHeight::from_u32(birthday),
        state: Mutex::default(),
    };
    let client = chain::connect_auto().await?;
    let tip = run(client, &key, Network::MainNetwork, &account).await?;

    let s = account.state.lock().unwrap();
    let balance: u64 = s.unspent.iter().map(|(.., value, _)| value).sum();
    match tip {
        Some(at) => println!("synced to {}: {balance} zat unspent", u32::from(at.height)),
        None => println!("birthday is beyond the chain tip; nothing to scan"),
    }
    Ok(())
}
