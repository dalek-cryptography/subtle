#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
#![doc(html_logo_url = "https://doc.dalek.rs/assets/dalek-logo-clear.png")]
// put this after the #![doc(..)] so it appears as a footer:
//! Note that docs will only build on nightly Rust until
//! [RFC 1990 stabilizes](https://github.com/rust-lang/rust/issues/44732).

extern crate byteorder;
extern crate clear_on_drop;
extern crate core;
extern crate keccak;
extern crate rand;
extern crate rand_core;

#[cfg(test)]
extern crate curve25519_dalek;
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

/// A transcript of a public-coin argument.
///
/// The prover's messages are added to the transcript using `commit_bytes`,
/// and the verifier's challenges can be computed using `challenge_bytes`.
///
/// # Usage
///
/// Implementations of proof protocols should take a `&mut Transcript`
/// as a parameter, **not** construct one internally.  This provides
/// three benefits:
///
/// 1.  It forces the API client to initialize their own transcript
/// using [`Transcript::new()`].  Since that function takes a domain
/// separation string, this ensures that all proofs are
/// domain-separated.
///
/// 2.  It ensures that protocols are sequentially composable, by
/// running them on a common transcript.  (Since transcript instances
/// are domain-separated, it should not be possible to extract a
/// sub-protocol's challenges and commitments as a standalone proof).
///
/// 3.  It allows API clients to commit contextual data to the
/// proof transcript prior to running the protocol, allowing them to
/// bind proof statements to arbitrary application data.
///
/// # Defining protocol behaviour with extension traits
///
/// This API is byte-oriented, while an actual protocol likely
/// requires typed data — for instance, a protocol probably wants to
/// receive challenge scalars, not challenge bytes.  The recommended
/// way to bridge this abstraction gap is to define a
/// protocol-specific extension trait.
///
/// For instance, consider a discrete-log based protocol which commits
/// to Ristretto points and requires challenge scalars for the
/// Ristretto group.  This protocol can define a protocol-specific
/// extension trait in its crate as follows:
/// ```
/// extern crate curve25519_dalek;
/// use curve25519_dalek::ristretto::CompressedRistretto;
/// use curve25519_dalek::scalar::Scalar;
///
/// extern crate merlin;
/// use merlin::Transcript;
///
/// trait TranscriptProtocol {
///     fn commit_point(&mut self, point: CompressedRistretto);
///     fn challenge_scalar(&mut self) -> Scalar;
/// }
///
/// impl TranscriptProtocol for Transcript {
///     fn commit_point(&mut self, point: CompressedRistretto) {
///         self.commit_bytes(b"pt", point.as_bytes());
///     }
///
///     fn challenge_scalar(&mut self) -> Scalar {
///         let mut buf = [0; 64];
///         self.challenge_bytes(b"sc", &mut buf);
///         Scalar::from_bytes_mod_order_wide(&buf)
///     }
/// }
/// # fn main() { }
/// ```
/// Now, the implementation of the protocol can call the
/// `commit_point` and `challenge_scalar` methods on any
/// [`Transcript`] instance, rather than calling [`commit_bytes`] and
/// [`challenge_bytes`] directly.  Note that in this example, the
/// functions in the extension trait don't assign semantic meaning to
/// the operations, but a better implementation of a real protocol
/// could define more meaningful functions like `commit_basepoint`,
/// `commit_pubkey`, etc., each with their own labels.
///
/// However, because the protocol-specific behaviour is defined in a
/// protocol-specific trait, different protocols can use the same
/// [`Transcript`] instance without imposing any extra type constraints.
#[derive(Clone)]
pub struct Transcript {
    strobe: Strobe128,
}

impl Transcript {
    /// Initialize a new transcript with the supplied `label`, which
    /// is used as a domain separator.
    ///
    /// # Note
    ///
    /// This function should be called by a protocol's API consumer,
    /// and *not* by the protocol implementation.
    pub fn new(label: &[u8]) -> Transcript {
        Transcript {
            strobe: Strobe128::new(label),
        }
    }

    /// Commit a prover's `message` to the transcript.
    ///
    /// The `label` parameter is metadata about the message, and is
    /// also committed to the transcript.
    pub fn commit_bytes(&mut self, label: &[u8], message: &[u8]) {
        let data_len = encode_usize(message.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.ad(message, false);
    }

    /// Fill the supplied buffer with the verifier's challenge bytes.
    ///
    /// The `label` parameter is metadata about the challenge, and is
    /// also committed to the transcript.
    pub fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        let data_len = encode_usize(dest.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.prf(dest, false);
    }

    /// Fork the current `Transcript` to construct an RNG whose output is bound
    /// to the current transcript state as well as prover's secrets.
    ///
    /// See the `TranscriptRng` documentation for more details.
    pub fn fork_transcript(&self) -> TranscriptRngConstructor {
        TranscriptRngConstructor {
            strobe: self.strobe.clone(),
        }
    }
}

/// The prover can commit secrets or randomness to the
/// `TranscriptRngConstructor` before finalizing to obtain a
/// `TranscriptRng` which is a PRF of the entire transcript as well as
/// the prover's secrets and randomness.
///
/// See the `TranscriptRng` documentation for more details.
pub struct TranscriptRngConstructor {
    strobe: Strobe128,
}

impl TranscriptRngConstructor {
    /// Commit witness data to the transcript, so that the finalized
    /// `TranscriptRng` is a PRF bound to `witness` as well as all
    /// other transcript data.
    ///
    /// The `label` parameter is metadata about the witness, and is
    /// also committed to the transcript.
    pub fn commit_witness_bytes(
        mut self,
        label: &[u8],
        witness: &[u8],
    ) -> TranscriptRngConstructor {
        let witness_len = encode_usize(witness.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&witness_len, true);
        self.strobe.key(witness, false);

        self
    }

    /// Use the supplied `rng` to rekey the transcript, so that the
    /// finalized `TranscriptRng` is a PRF bound to randomness from
    /// the external RNG, as well as all other transcript data.
    ///
    /// The input from the auxiliary RNG is modeled as an additional
    /// witness variable, and committed using `commit_witness`.
    pub fn rekey_rng<R>(self, rng: &mut R) -> TranscriptRngConstructor
    where
        R: rand::Rng + rand::CryptoRng,
    {
        let random_bytes = {
            let mut bytes = [0u8; 32];
            rng.fill(&mut bytes);
            bytes
        };

        self.commit_witness_bytes(b"rng", &random_bytes)
    }

    pub fn finalize(self) -> TranscriptRng {
        TranscriptRng {
            strobe: self.strobe,
        }
    }
}

pub struct TranscriptRng {
    strobe: Strobe128,
}

impl TranscriptRng {
    pub fn labeled_fill_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
        let dest_len = encode_usize(dest.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&dest_len, true);
        self.strobe.prf(dest, false);
    }
}

impl rand_core::RngCore for TranscriptRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // When using the TranscriptRng as a rand::Rng instance, we
        // don't get to set the label, so just use a fixed one
        self.labeled_fill_bytes(b"rng", dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        Ok(self.fill_bytes(dest))
    }
}

impl rand::CryptoRng for TranscriptRng {}

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
            TestTranscript {
                state: Strobe::new(label.to_vec(), SecParam::B128),
            }
        }

        /// Strobe op: meta-AD(label || len(message)); AD(message)
        pub fn commit_bytes(&mut self, label: &[u8], message: &[u8]) {
            // metadata = label || len(message);
            let metaflags: OpFlags = OpFlags::A | OpFlags::M;
            let mut metadata: Vec<u8> = Vec::with_capacity(label.len() + 4);
            metadata.extend_from_slice(label);
            metadata.extend_from_slice(&encode_usize(message.len()));

            self.state
                .ad(message.to_vec(), Some((metaflags, metadata)), false);
        }

        /// Strobe op: meta-AD(label || len(dest)); PRF into challenge_bytes
        pub fn challenge_bytes(&mut self, label: &[u8], dest: &mut [u8]) {
            let prf_len = dest.len();

            // metadata = label || len(challenge_bytes);
            let metaflags: OpFlags = OpFlags::A | OpFlags::M;
            let mut metadata: Vec<u8> = Vec::with_capacity(label.len() + 4);
            metadata.extend_from_slice(label);
            metadata.extend_from_slice(&encode_usize(prf_len));

            let bytes = self.state.prf(prf_len, Some((metaflags, metadata)), false);
            dest.copy_from_slice(&bytes);
        }
    }

    /// Test a simple protocol with one message and one challenge
    #[test]
    fn equivalence_simple() {
        let mut real_transcript = Transcript::new(b"test protocol");
        let mut test_transcript = TestTranscript::new(b"test protocol");

        real_transcript.commit_bytes(b"some label", b"some data");
        test_transcript.commit_bytes(b"some label", b"some data");

        let mut real_challenge = [0u8; 32];
        let mut test_challenge = [0u8; 32];

        real_transcript.challenge_bytes(b"challenge", &mut real_challenge);
        test_transcript.challenge_bytes(b"challenge", &mut test_challenge);

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

        real_transcript.commit_bytes(b"step1", b"some data");
        test_transcript.commit_bytes(b"step1", b"some data");

        let mut real_challenge = [0u8; 32];
        let mut test_challenge = [0u8; 32];

        for _ in 0..32 {
            real_transcript.challenge_bytes(b"challenge", &mut real_challenge);
            test_transcript.challenge_bytes(b"challenge", &mut test_challenge);

            assert_eq!(real_challenge, test_challenge);

            real_transcript.commit_bytes(b"bigdata", &data);
            test_transcript.commit_bytes(b"bigdata", &data);

            real_transcript.commit_bytes(b"challengedata", &real_challenge);
            test_transcript.commit_bytes(b"challengedata", &test_challenge);
        }
    }

    #[test]
    fn transcript_rng_is_bound_to_transcript_and_witnesses() {
        use curve25519_dalek::scalar::Scalar;
        use rand::prng::chacha::ChaChaRng;
        use rand::SeedableRng;

        // Check that the TranscriptRng is bound to the transcript and
        // the witnesses.  This is done by producing a sequence of
        // transcripts that diverge at different points and checking
        // that they produce different challenges.

        let protocol_label = b"test TranscriptRng collisions";
        let commitment1 = b"commitment data 1";
        let commitment2 = b"commitment data 2";
        let witness1 = b"witness data 1";
        let witness2 = b"witness data 2";

        let mut t1 = Transcript::new(protocol_label);
        let mut t2 = Transcript::new(protocol_label);
        let mut t3 = Transcript::new(protocol_label);
        let mut t4 = Transcript::new(protocol_label);

        t1.commit_bytes(b"com", commitment1);
        t2.commit_bytes(b"com", commitment2);
        t3.commit_bytes(b"com", commitment2);
        t4.commit_bytes(b"com", commitment2);

        let mut r1 = t1
            .fork_transcript()
            .commit_witness_bytes(b"witness", witness1)
            .rekey_rng(&mut ChaChaRng::from_seed([0; 32]))
            .finalize();

        let mut r2 = t2
            .fork_transcript()
            .commit_witness_bytes(b"witness", witness1)
            .rekey_rng(&mut ChaChaRng::from_seed([0; 32]))
            .finalize();

        let mut r3 = t3
            .fork_transcript()
            .commit_witness_bytes(b"witness", witness2)
            .rekey_rng(&mut ChaChaRng::from_seed([0; 32]))
            .finalize();

        let mut r4 = t4
            .fork_transcript()
            .commit_witness_bytes(b"witness", witness2)
            .rekey_rng(&mut ChaChaRng::from_seed([0; 32]))
            .finalize();

        let s1 = Scalar::random(&mut r1);
        let s2 = Scalar::random(&mut r2);
        let s3 = Scalar::random(&mut r3);
        let s4 = Scalar::random(&mut r4);

        // Transcript t1 has different commitments than t2, t3, t4, so
        // it should produce distinct challenges from all of them.
        assert_ne!(s1, s2);
        assert_ne!(s1, s3);
        assert_ne!(s1, s4);

        // Transcript t2 has different witness variables from t3, t4,
        // so it should produce distinct challenges from all of them.
        assert_ne!(s2, s3);
        assert_ne!(s2, s4);

        // Transcripts t3 and t4 have the same commitments and
        // witnesses, so they should give different challenges only
        // based on the RNG. Checking that they're equal in the
        // presence of a bad RNG checks that the different challenges
        // above aren't because the RNG is accidentally different.
        assert_eq!(s3, s4);
    }
}
