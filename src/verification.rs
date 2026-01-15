use sha3::{Digest, Sha3_256};

const SAFETY_NUMBER_DOMAIN: &[u8] = b"newspeak-safety-v1";
pub const SAFETY_NUMBER_GROUPS: usize = 10;

fn canonical_pair<'a>(left: &'a [u8; 32], right: &'a [u8; 32]) -> (&'a [u8; 32], &'a [u8; 32]) {
    if left <= right {
        (left, right)
    } else {
        (right, left)
    }
}

pub fn safety_number_hash(local: &[u8; 32], peer: &[u8; 32]) -> [u8; 32] {
    let (first, second) = canonical_pair(local, peer);
    let mut hasher = Sha3_256::new();
    hasher.update(SAFETY_NUMBER_DOMAIN);
    hasher.update(first);
    hasher.update(second);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

pub fn format_safety_number(hash: &[u8; 32]) -> String {
    let mut groups = Vec::with_capacity(SAFETY_NUMBER_GROUPS);
    for chunk in hash[..(SAFETY_NUMBER_GROUPS * 2)].chunks(2) {
        let value = u16::from_le_bytes([chunk[0], chunk[1]]);
        groups.push(format!("{:05}", value));
    }
    groups.join(" ")
}

pub fn safety_number_string(local: &[u8; 32], peer: &[u8; 32]) -> String {
    format_safety_number(&safety_number_hash(local, peer))
}

#[cfg(test)]
#[path = "tests/verification.rs"]
mod tests;
