use crate::errors::Error;
use crate::secp::GroupElement;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;
use once_cell::sync::Lazy;

const DOMAIN_SEPARATOR: &[u8; 28] = b"Secp256k1_HashToCurve_Cashu_";

pub fn hash_to_curve(message: &[u8]) -> Result<GroupElement, Error> {
    let msg_to_hash: Vec<u8> = [DOMAIN_SEPARATOR, message].concat();

    let msg_hash: [u8; 32] = Sha256Hash::hash(&msg_to_hash).to_byte_array();

    let mut counter: u32 = 0;
    while counter < 2_u32.pow(16) {
        let mut bytes_to_hash: Vec<u8> = Vec::with_capacity(36);
        bytes_to_hash.extend_from_slice(&msg_hash);
        bytes_to_hash.extend_from_slice(&counter.to_le_bytes());
        let mut hash: [u8; 33] = [0; 33];
        hash[0] = 0x02;
        hash[1..33].copy_from_slice(&Sha256Hash::hash(&bytes_to_hash).to_byte_array()[0..32]);

        // Try to parse public key
        match PublicKey::from_slice(&hash) {
            Ok(_) => return Ok(GroupElement::new(&hash)),
            Err(_) => {
                counter += 1;
            }
        }
    }

    Err(Error::InvalidPoint)
}

pub struct Generators {
    w: GroupElement,
    w_: GroupElement,
    x0: GroupElement,
    x1: GroupElement,
    gz_mac: GroupElement,
    gz_attribute: GroupElement,
    gz_script: GroupElement,
    g_amount: GroupElement,
    g_script: GroupElement,
    g_blind: GroupElement,
}

impl Generators {
    fn new() -> Self {
        let w = hash_to_curve(b"W").expect("Failed to hash to curve");
        let w_ = hash_to_curve(b"W_").expect("Failed to hash to curve");
        let x0 = hash_to_curve(b"X0").expect("Failed to hash to curve");
        let x1 = hash_to_curve(b"X1").expect("Failed to hash to curve");
        let gz_mac = hash_to_curve(b"Gz_mac").expect("Failed to hash to curve");
        let gz_attribute = hash_to_curve(b"Gz_attribute").expect("Failed to hash to curve");
        let gz_script = hash_to_curve(b"Gz_script").expect("Failed to hash to curve");
        let g_amount = hash_to_curve(b"G_amount").expect("Failed to hash to curve");
        let g_script = hash_to_curve(b"G_script").expect("Failed to hash to curve");
        let g_blind = hash_to_curve(b"G_blind").expect("Failed to hash to curve");

        Generators {
            w,
            w_,
            x0,
            x1,
            gz_mac,
            gz_attribute,
            gz_script,
            g_amount,
            g_script,
            g_blind,
        }
    }
}

pub static GENERATORS: Lazy<Generators> = Lazy::new(|| Generators::new());

#[cfg(test)]
mod tests {
    use crate::secp::GroupElement;

    use super::hash_to_curve;

    #[test]
    fn test_hash_to_curve() {
        let msg = b"G_amount";
        let g_amount = GroupElement::from(
            "024e76426e405fa7f7d3403ea8671fe11b8bec2da6dcda5583ce1ac37ed0de9b04",
        );
        let g_amount_ = hash_to_curve(msg).expect("Couldn't map hash to groupelement");
        assert!(g_amount == g_amount_)
    }

    #[test]
    fn test_hash_to_curve_2() {
        let msg = b"G_blind";
        let g_blind = GroupElement::from(
            "0264f39fbee428ab6165e907b5d463a17e315b9f06f6200ed7e9c4bcbe0df73383",
        );
        let g_blind_ = hash_to_curve(msg).expect("Couldn't map hash to groupelement");
        assert!(g_blind == g_blind_)
    }
}