use rand_core;

use strobe::Strobe128;

fn encode_u64(x: u64) -> [u8; 8] {
    use byteorder::{ByteOrder, LittleEndian};

    let mut buf = [0; 8];
    LittleEndian::write_u64(&mut buf, x);
    buf
}

fn encode_usize_as_u32(x: usize) -> [u8; 4] {
    use byteorder::{ByteOrder, LittleEndian};

    assert!(x <= (u32::max_value() as usize));

    let mut buf = [0; 4];
    LittleEndian::write_u32(&mut buf, x as u32);
    buf
}

/// A transcript of a public-coin argument.
///
/// The prover's messages are added to the transcript using `commit_bytes`,
/// and the verifier's challenges can be computed using `challenge_bytes`.
///
/// # Creating and using a Merlin transcript
///
/// To create a Merlin transcript, use [`Transcript::new()`].  This
/// function takes a domain separation label which should be unique to
/// the application.  To use the transcript with a Merlin-based proof
/// implementation, the prover's side creates a Merlin transcript with
/// an application-specific domain separation label, and passes a
/// `&mut` reference to the transcript to the proving function(s).  To
/// verify the resulting proof, the verifier creates their own Merlin
/// transcript using the same domain separation label, then passes a
/// `&mut` reference to the verifier's transcript to the verification
/// function.
///
/// # Implementing proofs using Merlin
///
/// Implementations of proof protocols should take a `&mut Transcript`
/// as a parameter, **not** construct one internally.  This provides
/// three benefits:
///
/// 1.  It forces the API client to initialize their own transcript
/// using [`Transcript::new()`].  Since that function takes a domain
/// separation string, this ensures that all proofs are
/// domain-separated, not just with a proof-specific domain separator,
/// but also with a per-application domain separator.
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
/// use curve25519_dalek::ristretto::RistrettoPoint;
/// use curve25519_dalek::ristretto::CompressedRistretto;
/// use curve25519_dalek::scalar::Scalar;
///
/// extern crate merlin;
/// use merlin::Transcript;
///
/// trait TranscriptProtocol {
///     fn domain_sep(&mut self);
///     fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto);
///     fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar;
/// }
///
/// impl TranscriptProtocol for Transcript {
///     fn domain_sep(&mut self) {
///         self.commit_bytes(b"dom-sep", b"TranscriptProtocol Example");
///     }
///
///     fn commit_point(&mut self, label: &'static [u8], point: &CompressedRistretto) {
///         self.commit_bytes(label, point.as_bytes());
///     }
///
///     fn challenge_scalar(&mut self, label: &'static [u8]) -> Scalar {
///         let mut buf = [0; 64];
///         self.challenge_bytes(label, &mut buf);
///         Scalar::from_bytes_mod_order_wide(&buf)
///     }
/// }
///
/// fn example(transcript: &mut Transcript, A: &RistrettoPoint, B: &RistrettoPoint) {
///     // Since the TranscriptProtocol trait is in scope, the extension
///     // methods are available on the `transcript` object:
///     transcript.domain_sep();
///     transcript.commit_point(b"A", &A.compress());
///     transcript.commit_point(b"B", &B.compress());
///     let c = transcript.challenge_scalar(b"c");
///     // ...
/// }
/// # fn main() { }
/// ```
/// Now, the implementation of the protocol can use the `domain_sep`
/// to add domain separation to an existing `&mut Transcript`, and
/// then call the `commit_point` and `challenge_scalar` methods,
/// rather than calling [`commit_bytes`][Transcript::commit_bytes] and
/// [`challenge_bytes`][Transcript::challenge_bytes] directly.
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
    /// and **not by the protocol implementation**.  See above for
    /// details.
    ///
    /// # Implementation
    ///
    /// Initializes a STROBE-128 context with a Merlin
    /// domain-separator label, then commits the user-supplied label
    /// using the STROBE operations
    /// ```text,no_run
    /// meta-AD( b"dom-sep" || LE32(label.len()) );
    /// AD( label );
    /// ```
    pub fn new(label: &'static [u8]) -> Transcript {
        use constants::MERLIN_PROTOCOL_LABEL;

        #[cfg(feature = "debug-transcript")]
        {
            use std::str::from_utf8;
            println!(
                "Initialize STROBE-128({})\t# b\"{}\"",
                hex::encode(MERLIN_PROTOCOL_LABEL),
                from_utf8(MERLIN_PROTOCOL_LABEL).unwrap(),
            );
        }

        let mut transcript = Transcript {
            strobe: Strobe128::new(MERLIN_PROTOCOL_LABEL),
        };
        transcript.commit_bytes(b"dom-sep", label);

        transcript
    }

    /// Commit a prover's `message` to the transcript.
    ///
    /// The `label` parameter is metadata about the message, and is
    /// also committed to the transcript.
    ///
    /// # Implementation
    ///
    /// Performs the STROBE operations
    /// ```text,no_run
    /// meta-AD( label || LE32(message.len()) );
    /// AD( message );
    /// ```
    pub fn commit_bytes(&mut self, label: &'static [u8], message: &[u8]) {
        let data_len = encode_usize_as_u32(message.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.ad(message, false);

        #[cfg(feature = "debug-transcript")]
        {
            use std::str::from_utf8;

            match from_utf8(label) {
                Ok(label_str) => {
                    println!(
                        "meta-AD : {} || LE32({})\t# b\"{}\"",
                        hex::encode(label),
                        message.len(),
                        label_str
                    );
                }
                Err(_) => {
                    println!(
                        "meta-AD : {} || LE32({})",
                        hex::encode(label),
                        message.len()
                    );
                }
            }
            match from_utf8(message) {
                Ok(message_str) => {
                    println!("     AD : {}\t# b\"{}\"", hex::encode(message), message_str);
                }
                Err(_) => {
                    println!("     AD : {}", hex::encode(message));
                }
            }
        }
    }

    /// Convenience method for committing a `u64` to the transcript.
    ///
    /// The `label` parameter is metadata about the message, and is
    /// also committed to the transcript.
    ///
    /// # Implementation
    ///
    /// Calls `commit_bytes` with the little-endian encoding of `x`.
    pub fn commit_u64(&mut self, label: &'static [u8], x: u64) {
        self.commit_bytes(label, &encode_u64(x));
    }

    /// Fill the supplied buffer with the verifier's challenge bytes.
    ///
    /// The `label` parameter is metadata about the challenge, and is
    /// also committed to the transcript.
    ///
    /// # Implementation
    ///
    /// Performs the STROBE operations
    /// ```text,no_run
    /// meta-AD( label || LE32(dest.len()) );
    /// dest <- PRF();
    /// ```
    pub fn challenge_bytes(&mut self, label: &'static [u8], dest: &mut [u8]) {
        let data_len = encode_usize_as_u32(dest.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&data_len, true);
        self.strobe.prf(dest, false);

        #[cfg(feature = "debug-transcript")]
        {
            use std::str::from_utf8;

            match from_utf8(label) {
                Ok(label_str) => {
                    println!(
                        "meta-AD : {} || LE32({})\t# b\"{}\"",
                        hex::encode(label),
                        dest.len(),
                        label_str
                    );
                }
                Err(_) => {
                    println!("meta-AD : {} || LE32({})", hex::encode(label), dest.len());
                }
            }
            println!("     PRF: {}", hex::encode(dest));
        }
    }

    /// Fork the current [`Transcript`] to construct an RNG whose output is bound
    /// to the current transcript state as well as prover's secrets.
    ///
    /// See the [`TranscriptRngBuilder`] documentation for more details.
    pub fn build_rng(&self) -> TranscriptRngBuilder {
        TranscriptRngBuilder {
            strobe: self.strobe.clone(),
        }
    }
}

/// Constructs a [`TranscriptRng`] by rekeying the [`Transcript`] with
/// prover secrets and an external RNG.
///
/// The prover commits witness data to the
/// [`TranscriptRngBuilder`] before using an external RNG to
/// finalize to a [`TranscriptRng`].  The resulting [`TranscriptRng`]
/// will be a PRF of all of the entire public transcript, the prover's
/// secret witness data, and randomness from the external RNG.
///
/// # Usage
///
/// To construct a [`TranscriptRng`], a prover calls
/// [`Transcript::build_rng()`] to clone the transcript state, then
/// uses [`commit_witness_bytes()`][commit_witness_bytes] to rekey the
/// transcript with the prover's secrets, before finally calling
/// [`finalize()`][finalize].  This rekeys the transcript with the
/// output of an external [`rand_core::RngCore`] instance and returns
/// a finalized [`TranscriptRng`].
///
/// These methods are intended to be chained, passing from a borrowed
/// [`Transcript`] to an owned [`TranscriptRng`] as follows:
/// ```
/// # extern crate merlin;
/// # extern crate rand;
/// # use merlin::Transcript;
/// # fn main() {
/// # let mut transcript = Transcript::new(b"TranscriptRng doctest");
/// # let public_data = b"public data";
/// # let witness_data = b"witness data";
/// # let more_witness_data = b"witness data";
/// transcript.commit_bytes(b"public", public_data);
///
/// let mut rng = transcript
///     .build_rng()
///     .commit_witness_bytes(b"witness1", witness_data)
///     .commit_witness_bytes(b"witness2", more_witness_data)
///     .finalize(&mut rand::thread_rng());
/// # }
/// ```
/// In this example, the final `rng` is a PRF of `public_data`
/// (as well as all previous `transcript` state), and of the prover's
/// secret `witness_data` and `more_witness_data`, and finally, of the
/// output of the thread-local RNG.
/// Note that because the [`TranscriptRng`] is produced from
/// [`finalize()`][finalize], it's impossible to forget
/// to rekey the transcript with external randomness.
///
/// # Note
///
/// Protocols that require randomness in multiple places (e.g., to
/// choose blinding factors for a multi-round protocol) should create
/// a fresh [`TranscriptRng`] **each time they need randomness**,
/// rather than reusing a single instance.  This ensures that the
/// randomness in each round is bound to the latest transcript state,
/// rather than just the state of the transcript when randomness was
/// first required.
///
/// # Typed Witness Data
///
/// Like the [`Transcript`], the [`TranscriptRngBuilder`] provides
/// a minimal, byte-oriented API, and like the [`Transcript`], this
/// API can be extended to allow committing protocol-specific types
/// using an extension trait.  See the [`Transcript`] documentation
/// for more details.
///
/// [commit_witness_bytes]: TranscriptRngBuilder::commit_witness_bytes
/// [finalize]: TranscriptRngBuilder::finalize
pub struct TranscriptRngBuilder {
    strobe: Strobe128,
}

impl TranscriptRngBuilder {
    /// Rekey the transcript using the provided witness data.
    ///
    /// The `label` parameter is metadata about `witness`, and is
    /// also committed to the transcript.
    ///
    /// # Implementation
    ///
    /// Performs the STROBE operations
    /// ```text,no_run
    /// meta-AD( label || LE32(witness.len()) );
    /// KEY( witness );
    /// ```
    pub fn commit_witness_bytes(
        mut self,
        label: &'static [u8],
        witness: &[u8],
    ) -> TranscriptRngBuilder {
        let witness_len = encode_usize_as_u32(witness.len());
        self.strobe.meta_ad(label, false);
        self.strobe.meta_ad(&witness_len, true);
        self.strobe.key(witness, false);

        self
    }

    /// Use the supplied external `rng` to rekey the transcript, so
    /// that the finalized [`TranscriptRng`] is a PRF bound to
    /// randomness from the external RNG, as well as all other
    /// transcript data.
    ///
    /// # Implementation
    ///
    /// Performs the STROBE operations
    /// ```text,no_run
    /// meta-AD( "rng" );
    /// KEY( 32 bytes of rng output );
    /// ```
    pub fn finalize<R>(mut self, rng: &mut R) -> TranscriptRng
    where
        R: rand_core::RngCore + rand_core::CryptoRng,
    {
        let random_bytes = {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            bytes
        };

        self.strobe.meta_ad(b"rng", false);
        self.strobe.key(&random_bytes, false);

        TranscriptRng {
            strobe: self.strobe,
        }
    }
}

/// An RNG providing synthetic randomness to the prover.
///
/// A [`TranscriptRng`] is constructed from a [`Transcript`] using a
/// [`TranscriptRngBuilder`]; see its documentation for details on
/// how to construct one.
///
/// # Design
///
/// The [`TranscriptRng`] provides a STROBE-based PRF for use by the
/// prover to generate random values for use in blinding factors, etc.
/// It's intended to generalize from
///
/// 1.  the deterministic nonce generation in Ed25519 & RFC 6979;
/// 2.  Trevor Perrin's ["synthetic" nonce generation for Generalised
/// EdDSA][trevp_synth];
/// 3.  and Mike Hamburg's nonce generation mechanism sketched in the
/// [STROBE paper][strobe_paper];
///
/// towards a design that's flexible enough for arbitrarily complex
/// public-coin arguments.
///
/// ## Deterministic and synthetic nonce generation
///
/// In Schnorr signatures (the context for the above designs), the
/// "nonce" is really a blinding factor used for a single
/// sigma-protocol (a proof of knowledge of the secret key, with the
/// message in the context); in a more complex protocol like
/// Bulletproofs, the prover runs a bunch of sigma protocols in
/// sequence and needs a bunch of blinding factors for each of them.
///
/// As noted in Trevor's mail, bad randomness in the blinding factor
/// can screw up Schnorr signatures in lots of ways:
///
/// * guessing the blinding reveals the secret;
/// * using the same blinding for two proofs reveals the secret;
/// * leaking a few bits of each blinding factor over many signatures
/// can allow recovery of the secret.
///
/// For more complex ZK arguments there's probably lots of even more
/// horrible ways that everything can go wrong.
///
/// In (1), the blinding factor is generated as the hash of both the
/// message data and a secret key unique to each signer, so that the
/// blinding factors are generated in a deterministic but secret way,
/// avoiding problems with bad randomness.  However, the choice to
/// make the blinding factors fully deterministic makes fault
/// injection attacks much easier, which has been used with some
/// success on Ed25519.
///
/// In (2), the blinding factor is generated as the hash of all of the
/// message data, some secret key, and some randomness from an
/// external RNG. This retains the benefits of (1), but without the
/// disadvantages of being fully deterministic.  Trevor terms this
/// "*synthetic nonce generation*".
///
/// The STROBE paper (3) describes a variant of (1) for performing
/// STROBE-based Schnorr signatures, where the blinding factor is
/// generated in the following way: first, the STROBE context is
/// copied; then, the signer uses a private key `k` to perform the
/// STROBE operations
/// ```text,no_run
/// KEY[sym-key](k);
/// r <- PRF[sig-determ]()
/// ```
///
/// The STROBE design is nice because forking the transcript exactly
/// when randomness is required ensures that, if the transcripts are
/// different, the blinding factor will be different -- no matter how
/// much extra data was fed into the transcript.  This means that even
/// though it's deterministic, it's automatically protected against an
/// issue Trevor mentioned:
///
/// > Without randomization, the algorithm is fragile to
/// > modifications and misuse.  In particular, modifying it to add an
/// > extra input to h=... without also adding the input to r=... would
/// > leak the private scalar if the same message is signed with a
/// > different extra input.  So would signing a message twice, once
/// > passing in an incorrect public key K (though the synthetic-nonce
/// > algorithm fixes this separately by hashing K into r).
///
/// ## Transcript-based synthetic randomness
///
/// To combine (2) and (3), the [`TranscriptRng`] provides a PRF of
/// the [`Transcript`] state, prover secrets, and the output of an
/// external RNG, to combine (2) and (3).  In Merlin's setting, the
/// only secrets available to the prover are the witness variables for
/// the proof statement, so in the presence of a weak or failing RNG,
/// the "backup" entropy is limited to the entropy of the witness
/// variables.
///
/// The [`TranscriptRng`] is produced from a
/// [`TranscriptRngBuilder`], which allows the prover to rekey the
/// STROBE state with arbitrary witness data, and then forces the
/// prover to rekey the STROBE state with the output of an external
/// [`rand_core::RngCore`] instance.  The [`TranscriptRng`] then uses STROBE
/// `PRF` operations to provide randomness.
///
/// Binding the output to the [`Transcript`] state ensures that two
/// different proof contexts always generate different outputs.  This
/// prevents repeating blinding factors between proofs.  Binding the
/// output to the prover's witness data ensures that the PRF output
/// has at least as much entropy as the witness does.  Finally,
/// binding the output to the output of an external RNG provides a
/// backstop and avoids the downsides of fully deterministic generation.
///
/// [trevp_synth]: https://moderncrypto.org/mail-archive/curves/2017/000925.html
/// [strobe_paper]: https://strobe.sourceforge.io/papers/strobe-20170130.pdf
pub struct TranscriptRng {
    strobe: Strobe128,
}

impl rand_core::RngCore for TranscriptRng {
    fn next_u32(&mut self) -> u32 {
        rand_core::impls::next_u32_via_fill(self)
    }

    fn next_u64(&mut self) -> u64 {
        rand_core::impls::next_u64_via_fill(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let dest_len = encode_usize_as_u32(dest.len());
        self.strobe.meta_ad(&dest_len, false);
        self.strobe.prf(dest, false);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for TranscriptRng {}

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
            use constants::MERLIN_PROTOCOL_LABEL;

            let mut tt = TestTranscript {
                state: Strobe::new(MERLIN_PROTOCOL_LABEL.to_vec(), SecParam::B128),
            };
            tt.commit_bytes(b"dom-sep", label);

            tt
        }

        /// Strobe op: meta-AD(label || len(message)); AD(message)
        pub fn commit_bytes(&mut self, label: &[u8], message: &[u8]) {
            // metadata = label || len(message);
            let metaflags: OpFlags = OpFlags::A | OpFlags::M;
            let mut metadata: Vec<u8> = Vec::with_capacity(label.len() + 4);
            metadata.extend_from_slice(label);
            metadata.extend_from_slice(&encode_usize_as_u32(message.len()));

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
            metadata.extend_from_slice(&encode_usize_as_u32(prf_len));

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
        use rand::SeedableRng;
        use rand_chacha::ChaChaRng;

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
            .build_rng()
            .commit_witness_bytes(b"witness", witness1)
            .finalize(&mut ChaChaRng::from_seed([0; 32]));

        let mut r2 = t2
            .build_rng()
            .commit_witness_bytes(b"witness", witness1)
            .finalize(&mut ChaChaRng::from_seed([0; 32]));

        let mut r3 = t3
            .build_rng()
            .commit_witness_bytes(b"witness", witness2)
            .finalize(&mut ChaChaRng::from_seed([0; 32]));

        let mut r4 = t4
            .build_rng()
            .commit_witness_bytes(b"witness", witness2)
            .finalize(&mut ChaChaRng::from_seed([0; 32]));

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
