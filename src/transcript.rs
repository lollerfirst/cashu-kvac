use merlin::Transcript;

use crate::secp::{GroupElement, Scalar};

pub struct CashuTranscript {
    inner: Transcript
}

impl CashuTranscript {
    pub fn new() -> Self {
        let inner = Transcript::new(b"Secp256k1_Cashu_");
        CashuTranscript { inner }
    }

    pub fn domain_sep(&mut self, message: &[u8]) {
        self.inner.append_message(b"dom-sep", message);
    }

    pub fn append_element(&mut self, label: &'static [u8], element: &GroupElement) {
        let element_bytes_compressed: [u8; 33] = element.into();
        self.inner.append_message(label, &element_bytes_compressed);
    }

    pub fn get_challenge(&mut self, label: &'static [u8]) -> Scalar {
        let mut challenge: [u8; 32] = [0; 32];
        self.inner.challenge_bytes(label, &mut challenge);
        Scalar::new(&challenge)
    }
}

impl AsMut<CashuTranscript> for CashuTranscript {
    fn as_mut(&mut self) -> &mut Self {
        self
    }
}