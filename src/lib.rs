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
            let mut data: Vec<u8> = Vec::with_capacity(label.len() + 4);
            data.extend_from_slice(label);
            data.extend_from_slice(&encode_usize(message.len()));

            let flags: OpFlags = OpFlags::A | OpFlags::M;
            let _ = self
                .state
                .ad(data.clone(), Some((flags, data.clone())), false);

            let mut msg: Vec<u8> = Vec::with_capacity(message.len());
            msg.extend_from_slice(message);

            self.state.ad(msg, None, false);
        }

        /// Strobe op: meta-AD(label || len(challenge_bytes)); PRF into challenge_bytes
        pub fn challenge(&mut self, label: &[u8], challenge_bytes: &mut [u8]) {
            let mut data: Vec<u8> = Vec::with_capacity(label.len() + 4);
            data.extend_from_slice(label);
            data.extend_from_slice(&encode_usize(challenge_bytes.len()));

            let flags: OpFlags = OpFlags::A | OpFlags::M;
            let _ = self
                .state
                .ad(data.clone(), Some((flags, data.clone())), false);

            let bytes: Vec<u8> = self.state.prf(challenge_bytes.len(), None, false);

            challenge_bytes.copy_from_slice(&bytes[..]);
        }
    }

    #[test]
    fn commit_and_challenge_should_match() {
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
}
