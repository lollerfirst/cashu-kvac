//! A Rust testing harness for the C implementation.
// This entire crate is only for tests, so it's all unused without cfg(test)
#![allow(dead_code)]

#[cfg(test)]
extern crate merlin;
#[cfg(test)]
extern crate rand;
#[cfg(test)]
extern crate rand_chacha;
extern crate rand_core;

// should be the right size?
#[repr(C)]
struct CTranscript {
    state: [u8; 203],
}

// should be the right size?
#[repr(C)]
struct CRng {
    state: [u8; 204],
}

extern "C" {
    fn merlin_transcript_init(mctx: *mut CTranscript, label: *const u8, label_len: usize);

    fn merlin_transcript_commit_bytes(
        mctx: *mut CTranscript,
        label: *const u8,
        label_len: usize,
        data: *const u8,
        data_len: usize,
    );

    fn merlin_transcript_challenge_bytes(
        mctx: *mut CTranscript,
        label: *const u8,
        label_len: usize,
        buffer: *mut u8,
        buffer_len: usize,
    );

    fn merlin_rng_init(mrng: *mut CRng, mctx: *const CTranscript);

    fn merlin_rng_commit_witness_bytes(
        mrng: *mut CRng,
        label: *const u8,
        label_len: usize,
        witness: *const u8,
        witness_len: usize,
    );

    fn merlin_rng_finalize(mrng: *mut CRng, entropy: &[u8; 32]);

    fn merlin_rng_random_bytes(mrng: *mut CRng, buffer: *mut u8, buffer_len: usize);

    fn merlin_rng_wipe(mrng: *mut CRng);
}

pub struct Transcript {
    mctx: CTranscript,
}

impl Transcript {
    pub fn new(label: &'static [u8]) -> Transcript {
        let mut mctx = CTranscript { state: [99u8; 203] };
        unsafe {
            merlin_transcript_init(&mut mctx, label.as_ptr(), label.len());
        }
        Transcript { mctx }
    }

    pub fn commit_bytes(&mut self, label: &'static [u8], message: &[u8]) {
        unsafe {
            merlin_transcript_commit_bytes(
                &mut self.mctx,
                label.as_ptr(),
                label.len(),
                message.as_ptr(),
                message.len(),
            );
        }
    }

    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        unsafe {
            merlin_transcript_challenge_bytes(
                &mut self.mctx,
                label.as_ptr(),
                label.len(),
                dest.as_mut_ptr(),
                dest.len(),
            );
        }
    }

    pub fn build_rng(&self) -> TranscriptRngBuilder {
        let mut mrng = CRng { state: [99u8; 204] };
        unsafe {
            merlin_rng_init(&mut mrng, &self.mctx);
        }
        TranscriptRngBuilder { mrng }
    }
}

pub struct TranscriptRngBuilder {
    mrng: CRng,
}

impl TranscriptRngBuilder {
    pub fn commit_witness_bytes(
        mut self,
        label: &'static [u8],
        witness: &[u8],
    ) -> TranscriptRngBuilder {
        unsafe {
            merlin_rng_commit_witness_bytes(
                &mut self.mrng,
                label.as_ptr(),
                label.len(),
                witness.as_ptr(),
                witness.len(),
            );
        }

        self
    }

    pub fn finalize<R>(mut self, rng: &mut R) -> TranscriptRng
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let random_bytes = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        unsafe {
            merlin_rng_finalize(&mut self.mrng, &random_bytes);
        }

        TranscriptRng { mrng: self.mrng }
    }
}

pub struct TranscriptRng {
    mrng: CRng,
}

impl rand_core::RngCore for TranscriptRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        unsafe {
            merlin_rng_random_bytes(&mut self.mrng, dest.as_mut_ptr(), dest.len());
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl Drop for TranscriptRng {
    fn drop(&mut self) {
        unsafe {
            merlin_rng_wipe(&mut self.mrng);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::Rng;
    use rand_chacha::ChaChaRng;
    use rand_core::{RngCore, SeedableRng};

    #[test]
    fn randomized_transcript_conformance() {
        let num_runs = 100;
        for _ in 0..num_runs {
            random_transcript_run();
        }
    }

    #[test]
    fn basic_transcript_conformance() {
        let mut rs_transcript = merlin::Transcript::new(b"ConformanceTest");
        let mut c_transcript = Transcript::new(b"ConformanceTest");

        rs_transcript.commit_bytes(b"data", b"testdata");
        c_transcript.commit_bytes(b"data", b"testdata");

        let mut rs_chal = [0u8; 32];
        let mut c_chal = [0u8; 32];

        rs_transcript.challenge_bytes(b"chal", &mut rs_chal);
        c_transcript.challenge_bytes(b"chal", &mut c_chal);

        assert_eq!(c_chal, rs_chal);

        let mut rs_rng = rs_transcript
            .build_rng()
            .commit_witness_bytes(b"witness", b"witnessdata")
            .finalize(&mut ChaChaRng::from_seed([17; 32]));
        let mut c_rng = rs_transcript
            .build_rng()
            .commit_witness_bytes(b"witness", b"witnessdata")
            .finalize(&mut ChaChaRng::from_seed([17; 32]));

        rs_rng.fill_bytes(&mut rs_chal);
        c_rng.fill_bytes(&mut c_chal);

        assert_eq!(c_chal, rs_chal);
    }

    fn random_transcript_run() {
        let mut rs_transcript = merlin::Transcript::new(b"ConformanceTest");
        let mut c_transcript = Transcript::new(b"ConformanceTest");

        let max_test_data_size = 64 * 1024;
        let mut message_data = vec![0u8; max_test_data_size];
        let mut rs_chal_buf = vec![0u8; max_test_data_size];
        let mut c_chal_buf = vec![0u8; max_test_data_size];

        let num_operations = 1_000;
        let mut rng = rand::thread_rng();

        for _ in 0..num_operations {
            let op_len = rng.gen_range(0, max_test_data_size);
            if rng.gen::<bool>() {
                rng.fill(&mut message_data[0..op_len]);
                rs_transcript.commit_bytes(b"data", &message_data[0..op_len]);
                c_transcript.commit_bytes(b"data", &message_data[0..op_len]);
            } else {
                rs_transcript.challenge_bytes(b"chal", &mut rs_chal_buf[0..op_len]);
                c_transcript.challenge_bytes(b"chal", &mut c_chal_buf[0..op_len]);
                assert_eq!(&rs_chal_buf[0..op_len], &c_chal_buf[0..op_len]);
            }
        }

        let mut rs_chal = [0u8; 32];
        let mut c_chal = [0u8; 32];

        rs_transcript.challenge_bytes(b"finalchal", &mut rs_chal);
        c_transcript.challenge_bytes(b"finalchal", &mut c_chal);

        assert_eq!(c_chal, rs_chal);
    }
}
