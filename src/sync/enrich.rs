//! Memo enrichment: fetch the full transactions behind owned notes and recover
//! their memos.
//!
//! Compact blocks truncate each output's ciphertext to 52 bytes — enough to
//! recover the note (value, recipient, nullifier, position), but not the memo,
//! which lives in the full 580-byte ciphertext. [`enrich_memos`] fetches the
//! full transaction for the (few) notes we own, decrypts the matching output
//! with the pool's incoming viewing key, and attaches the raw 512-byte memo.
//!
//! This is network IO but not persistence — it operates on an in-memory
//! [`Scanned`] and works with or without the `db` engine.

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use zcash_primitives::transaction::components::sapling::zip212_enforcement;
use zcash_primitives::transaction::Transaction;
use zcash_protocol::consensus::{BlockHeight, BranchId, Network};

use crate::keys::ScanningKeys;
use crate::note::decrypt::{try_decrypt_orchard, try_decrypt_sapling};
use crate::sync::chain::{self, LwdClient};
use crate::sync::Scanned;

/// Fill in the `memo` of every owned note in `scanned` for which we can recover
/// one, by fetching each owning transaction and decrypting its outputs.
///
/// Each owning transaction is fetched at most once. **Best-effort:** the note,
/// balance, and spend data already came from the compact block, so a failed
/// fetch or parse just leaves `memo = None` rather than failing the sync.
pub async fn enrich_memos(
    client: &mut LwdClient,
    keys: &ScanningKeys,
    network: &Network,
    scanned: &mut Scanned,
) {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));

    // Distinct txids of owned notes — fetch each full transaction once.
    let mut txids: Vec<[u8; 32]> = scanned
        .sapling
        .iter()
        .map(|n| n.txid)
        .chain(scanned.orchard.iter().map(|n| n.txid))
        .collect();
    txids.sort_unstable();
    txids.dedup();

    for txid in txids {
        let Ok(raw) = chain::fetch_raw_transaction(client, &txid).await else {
            continue;
        };
        let height = BlockHeight::from_u32(raw.height as u32);
        let Ok(tx) = Transaction::read(&raw.data[..], BranchId::for_height(network, height)) else {
            continue;
        };

        if let (Some(ivk), Some(bundle)) = (&sapling_ivk, tx.sapling_bundle()) {
            let outputs = bundle.shielded_outputs();
            for note in scanned
                .sapling
                .iter_mut()
                .filter(|n| n.txid == txid && n.memo.is_none())
            {
                if let Some(output) = outputs.get(note.output_index as usize) {
                    let zip212 = zip212_enforcement(network, BlockHeight::from_u32(note.height));
                    if let Some((.., memo)) = try_decrypt_sapling(output, ivk, zip212) {
                        note.memo = Some(memo);
                    }
                }
            }
        }

        if let (Some(ivk), Some(bundle)) = (&orchard_ivk, tx.orchard_bundle()) {
            let actions = bundle.actions();
            for note in scanned
                .orchard
                .iter_mut()
                .filter(|n| n.txid == txid && n.memo.is_none())
            {
                if let Some(action) = actions.get(note.action_index as usize) {
                    if let Some((.., memo)) = try_decrypt_orchard(action, ivk) {
                        note.memo = Some(memo);
                    }
                }
            }
        }
    }
}
