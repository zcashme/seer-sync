//! Trial-decrypt compact blocks with a viewing key — and, with a full key,
//! detect spends and compute a balance.
//!
//! Incoming detection runs the `sapling` / `orchard` batch trial-decryption
//! over every compact output and action. When the keys carry nullifier-deriving
//! material (a full key), each received Orchard note's nullifier is derived and
//! matched against the spends seen in the scanned blocks. Sapling spend
//! detection additionally needs leaf-position tracking, which isn't wired yet.

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
    /// be derived). Always `false` for Sapling, which still lacks
    /// leaf-position tracking.
    pub spent: bool,
}

/// Notes received across the scanned blocks, grouped by pool.
#[derive(Default)]
pub struct Received {
    /// Sapling notes (spend detection not yet wired — `spent` is always false).
    pub sapling: Vec<ReceivedNote<sapling::Note, sapling::PaymentAddress>>,
    /// Orchard notes (spend-detected when scanned with a full key).
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
/// received Orchard notes spent when `keys` carries nullifier-deriving keys.
pub fn sync(blocks: &[CompactBlock], keys: &ScanningKeys) -> Received {
    let sapling_ivk = keys.sapling.as_ref().map(|k| k.ivk.prepare());
    let orchard_ivk = keys.orchard.as_ref().map(|k| OrchardPreparedIvk::new(&k.ivk));
    let orchard_nk = keys.orchard.as_ref().and_then(|k| k.nk.as_ref());

    let mut sapling = Vec::new();
    let mut orchard: Vec<(u32, orchard::Note, orchard::Address, Option<[u8; 32]>)> = Vec::new();
    let mut spends: HashSet<[u8; 32]> = HashSet::new();

    for block in blocks {
        let height = block.height as u32;

        if let Some(ivk) = &sapling_ivk {
            let inputs: Vec<(SaplingDomain, CompactOutputDescription)> = block
                .vtx
                .iter()
                .flat_map(|tx| &tx.outputs)
                .filter_map(parse_sapling)
                .map(|o| (SaplingDomain::new(Zip212Enforcement::On), o))
                .collect();
            for ((note, recipient), _) in
                batch::try_compact_note_decryption(std::slice::from_ref(ivk), &inputs)
                    .into_iter()
                    .flatten()
            {
                sapling.push(ReceivedNote { height, note, recipient, spent: false });
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

        // Every Orchard action reveals the nullifier of the note it spends.
        for tx in &block.vtx {
            for action in &tx.actions {
                if let Ok(nf) = action.nullifier[..].try_into() {
                    spends.insert(nf);
                }
            }
        }
    }

    let orchard = orchard
        .into_iter()
        .map(|(height, note, recipient, nf)| ReceivedNote {
            height,
            note,
            recipient,
            spent: nf.is_some_and(|nf| spends.contains(&nf)),
        })
        .collect();

    Received { sapling, orchard }
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
