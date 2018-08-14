extern crate byteorder;
extern crate core;
extern crate keccak;

#[cfg(test)]
extern crate strobe_rs;

mod strobe;

use strobe::Strobe128;

fn encode_usize(x: usize) -> [u8; 4] {
    use byteorder::{ByteOrder, LittleEndian};

    assert!(x < (u32::max_value() as usize));

    let mut buf = [0; 4];
    LittleEndian::write_u32(&mut buf, x as u32);
    buf
}

/// Transcript of a public coin argument
#[derive(Clone)]
pub struct Transcript {
    strobe: Strobe128,
}

impl Transcript {
    /// Initialize a new transcript with the supplied label.
    pub fn new(label: &[u8]) -> Transcript {
        Transcript {
            strobe: Strobe128::new(label),
        }
    }

    /// Commit a prover's message to the transcript.
    pub fn commit(&mut self, label: &[u8], message: &[u8]) {
        let data_len = encode_usize(message.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.ad(message, false);
    }

    /// Fill the supplied buffer with the verifier's challenge bytes.
    pub fn challenge(&mut self, label: &[u8], challenge_bytes: &mut [u8]) {
        let data_len = encode_usize(challenge_bytes.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.prf(challenge_bytes, false);
    }
}

#[cfg(test)]
mod tests {
    use strobe_rs::OpFlags;
    use strobe_rs::SecParam;
    use strobe_rs::Strobe;

    use super::*;

    /// Test against a full strobe implementation to ensure we match the few
    /// operations we're interested in.
    struct TestTranscript {
        state: Strobe,
    }

    impl TestTranscript {
        /// Strobe init; meta-AD(label)
        pub fn new(label: &[u8]) -> TestTranscript {
            // XXX the new() method is doing an AD[label]() operation
            let mut strobe: Strobe = Strobe::new(label.to_vec(), SecParam::B128);

            TestTranscript { state: strobe }
        }

        /// Strobe op: meta-AD(label || len(message)); AD(message)
        pub fn commit(&mut self, label: &[u8], message: &[u8]) {
            // metadata = label || len(message);
            let metaflags: OpFlags = OpFlags::A | OpFlags::M;
            let mut metadata: Vec<u8> = Vec::with_capacity(label.len() + 4);
            metadata.extend_from_slice(label);
            metadata.extend_from_slice(&encode_usize(message.len()));

            self.state
                .ad(message.to_vec(), Some((metaflags, metadata)), false);
        }

        /// Strobe op: meta-AD(label || len(challenge_bytes)); PRF into challenge_bytes
        pub fn challenge(&mut self, label: &[u8], challenge_bytes: &mut [u8]) {
            let prf_len = challenge_bytes.len();

            // metadata = label || len(challenge_bytes);
            let metaflags: OpFlags = OpFlags::A | OpFlags::M;
            let mut metadata: Vec<u8> = Vec::with_capacity(label.len() + 4);
            metadata.extend_from_slice(label);
            metadata.extend_from_slice(&encode_usize(prf_len));

            let bytes = self.state.prf(prf_len, Some((metaflags, metadata)), false);
            challenge_bytes.copy_from_slice(&bytes);
        }
    }

    /// Test a simple protocol with one message and one challenge
    #[test]
    fn equivalence_simple() {
        let mut real_transcript = Transcript::new(b"test protocol");
        let mut test_transcript = TestTranscript::new(b"test protocol");

        real_transcript.commit(b"some label", b"some data");
        test_transcript.commit(b"some label", b"some data");

        let mut real_challenge = [0u8; 32];
        let mut test_challenge = [0u8; 32];

        real_transcript.challenge(b"challenge", &mut real_challenge);
        test_transcript.challenge(b"challenge", &mut test_challenge);

        assert_eq!(real_challenge, test_challenge);
    }

    /// Test a complex protocol with multiple messages and challenges,
    /// with messages long enough to wrap around the sponge state, and
    /// with multiple rounds of messages and challenges.
    #[test]
    fn equivalence_complex() {
        let mut real_transcript = Transcript::new(b"test protocol");
        let mut test_transcript = TestTranscript::new(b"test protocol");

        let data = vec![99; 1024];

        real_transcript.commit(b"step1", b"some data");
        test_transcript.commit(b"step1", b"some data");

        let mut real_challenge = [0u8; 32];
        let mut test_challenge = [0u8; 32];

        for i in 0..32 {
            real_transcript.challenge(b"challenge", &mut real_challenge);
            test_transcript.challenge(b"challenge", &mut test_challenge);

            assert_eq!(real_challenge, test_challenge);

            real_transcript.commit(b"bigdata", &data);
            test_transcript.commit(b"bigdata", &data);

            real_transcript.commit(b"challengedata", &real_challenge);
            test_transcript.commit(b"challengedata", &test_challenge);
        }
    }
}
