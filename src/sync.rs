//! Trial-decrypt compact blocks with a viewing key — and, with a full key,
//! detect spends and compute a balance.
//!
//! Incoming detection runs the `sapling` / `orchard` batch trial-decryption
//! over every compact output and action. When the keys carry nullifier-deriving
//! material (a full key), each received note's nullifier is derived and matched
//! against the spends seen in the scanned blocks. Sapling nullifiers also need
//! the note's leaf position, taken from each block's `chain_metadata`
//! (the Sapling tree size lightwalletd stamps on the block).

use std::collections::HashSet;

pub mod chain;

use orchard::keys::PreparedIncomingViewingKey as OrchardPreparedIvk;
use orchard::note_encryption::{CompactAction, OrchardDomain};
use sapling::note_encryption::{CompactOutputDescription, SaplingDomain, Zip212Enforcement};
use zcash_note_encryption::{batch, EphemeralKeyBytes};

use crate::keys::ScanningKeys;
use crate::proto::{CompactBlock, CompactOrchardAction, CompactSaplingOutput};

/// A note received while scanning.
pub struct ReceivedNote<N, A> {
    /// Block height the note was received at.
    pub height: u32,
    /// The decrypted note (the `sapling` / `orchard` crate's own type).
    pub note: N,
    /// Recipient address recovered from the plaintext.
    pub recipient: A,
    /// Whether the note was seen spent within the scanned range.
    ///
    /// Only ever `true` when scanning with a full key (so the nullifier could
    /// be derived) — and, for Sapling, when the block carried the
    /// `chain_metadata` needed to compute the note's leaf position.
    pub spent: bool,
}

/// Notes received across the scanned blocks, grouped by pool.
#[derive(Default)]
pub struct Received {
    /// Sapling notes received.
    pub sapling: Vec<ReceivedNote<sapling::Note, sapling::PaymentAddress>>,
    /// Orchard notes received.
    pub orchard: Vec<ReceivedNote<orchard::Note, orchard::Address>>,
}

/// Received / spent / unspent totals, in zatoshis.
#[derive(Debug, Default, Clone, Copy)]
pub struct Balance {
    /// Total value of all notes received.
    pub received: u64,
    /// Total value of received notes seen spent within the scanned range.
    pub spent: u64,
    /// `received - spent`.
    pub unspent: u64,
}

impl Received {
    /// Sum received, spent, and unspent value across both pools.
    pub fn balance(&self) -> Balance {
        let received = self.sapling.iter().map(|n| n.note.value().inner()).sum::<u64>()
            + self.orchard.iter().map(|n| n.note.value().inner()).sum::<u64>();
        let spent = self.sapling.iter().filter(|n| n.spent).map(|n| n.note.value().inner()).sum::<u64>()
            + self.orchard.iter().filter(|n| n.spent).map(|n| n.note.value().inner()).sum::<u64>();
        Balance { received, spent, unspent: received - spent }
    }
}

/// Trial-decrypt every Sapling output and Orchard action in `blocks`, flagging
/// received notes spent when `keys` carries nullifier-deriving keys.
pub fn sync(blocks: &[CompactBlock], keys: &ScanningKeys) -> Received {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let sapling_nk = keys.sapling.as_ref().and_then(|k| k.nk.as_ref());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));
    let orchard_nk = keys.orchard.as_ref().and_then(|k| k.nk.as_ref());

    let mut sapling: Vec<(u32, sapling::Note, sapling::PaymentAddress, Option<[u8; 32]>)> =
        Vec::new();
    let mut orchard: Vec<(u32, orchard::Note, orchard::Address, Option<[u8; 32]>)> = Vec::new();
    let mut spends: HashSet<[u8; 32]> = HashSet::new();

    for block in blocks {
        let height = block.height as u32;

        if let Some(ivk) = &sapling_ivk {
            // Leaf position of this block's first Sapling output, from the tree
            // size stamped on the block (post-block size − outputs in block).
            let block_start = block.chain_metadata.as_ref().map(|m| {
                let after = m.sapling_commitment_tree_size as u64;
                let in_block: u64 = block.vtx.iter().map(|tx| tx.outputs.len() as u64).sum();
                after.saturating_sub(in_block)
            });

            // Count *every* output for positions, but only feed parseable ones
            // to batch decryption; `positions[i]` aligns with the i-th input.
            let mut inputs: Vec<(SaplingDomain, CompactOutputDescription)> = Vec::new();
            let mut positions: Vec<Option<u64>> = Vec::new();
            let mut idx = 0u64;
            for tx in &block.vtx {
                for out in &tx.outputs {
                    let pos = block_start.map(|s| s + idx);
                    idx += 1;
                    if let Some(desc) = parse_sapling(out) {
                        inputs.push((SaplingDomain::new(Zip212Enforcement::On), desc));
                        positions.push(pos);
                    }
                }
            }

            for (i, hit) in batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                .into_iter()
                .enumerate()
            {
                if let Some(((note, recipient), _)) = hit {
                    let nullifier = match (sapling_nk, positions[i]) {
                        (Some(nk), Some(pos)) => Some(note.nf(nk, pos).0),
                        _ => None,
                    };
                    sapling.push((height, note, recipient, nullifier));
                }
            }
        }

        if let Some(ivk) = &orchard_ivk {
            let inputs: Vec<(OrchardDomain, CompactAction)> = block
                .vtx
                .iter()
                .flat_map(|tx| &tx.actions)
                .filter_map(parse_orchard)
                .map(|a| (OrchardDomain::for_compact_action(&a), a))
                .collect();
            for ((note, recipient), _) in
                batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                    .into_iter()
                    .flatten()
            {
                let nullifier = orchard_nk.map(|fvk| note.nullifier(fvk).to_bytes());
                orchard.push((height, note, recipient, nullifier));
            }
        }

        // Spends seen this block: Orchard actions reveal a nullifier each, and
        // Sapling spends carry theirs directly.
        for tx in &block.vtx {
            for action in &tx.actions {
                if let Ok(nf) = action.nullifier[..].try_into() {
                    spends.insert(nf);
                }
            }
            for spend in &tx.spends {
                if let Ok(nf) = spend.nf[..].try_into() {
                    spends.insert(nf);
                }
            }
        }
    }

    let spent_of = |nf: Option<[u8; 32]>| nf.is_some_and(|nf| spends.contains(&nf));

    Received {
        sapling: sapling
            .into_iter()
            .map(|(height, note, recipient, nf)| ReceivedNote {
                height,
                note,
                recipient,
                spent: spent_of(nf),
            })
            .collect(),
        orchard: orchard
            .into_iter()
            .map(|(height, note, recipient, nf)| ReceivedNote {
                height,
                note,
                recipient,
                spent: spent_of(nf),
            })
            .collect(),
    }
}

/// Proto → `sapling` compact output. Deserialization glue, not crypto.
fn parse_sapling(p: &CompactSaplingOutput) -> Option<CompactOutputDescription> {
    let cmu_bytes: [u8; 32] = p.cmu[..].try_into().ok()?;
    let cmu = Option::from(sapling::note::ExtractedNoteCommitment::from_bytes(&cmu_bytes))?;
    let ephemeral_key = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let enc_ciphertext = p.ciphertext[..].try_into().ok()?;
    Some(CompactOutputDescription { cmu, ephemeral_key, enc_ciphertext })
}

/// Proto → `orchard` compact action. Deserialization glue, not crypto.
fn parse_orchard(p: &CompactOrchardAction) -> Option<CompactAction> {
    let nf: [u8; 32] = p.nullifier[..].try_into().ok()?;
    let nf = Option::from(orchard::note::Nullifier::from_bytes(&nf))?;
    let cmx: [u8; 32] = p.cmx[..].try_into().ok()?;
    let cmx = Option::from(orchard::note::ExtractedNoteCommitment::from_bytes(&cmx))?;
    let epk = EphemeralKeyBytes(p.ephemeral_key[..].try_into().ok()?);
    let ct: [u8; 52] = p.ciphertext[..].try_into().ok()?;
    Some(CompactAction::from_parts(nf, cmx, epk, ct))
}
