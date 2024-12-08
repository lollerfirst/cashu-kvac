use crate::errors::Error;
use crate::secp::GroupElement;
use bitcoin::hashes::sha256::Hash as Sha256Hash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::PublicKey;

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
            Ok(_) => {
               return Ok(GroupElement::new(&hash))
            }
            Err(_) => {
                counter += 1;
            }
        } 
    }

    Err(Error::InvalidPoint)
}