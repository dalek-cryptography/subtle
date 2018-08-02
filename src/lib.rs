/// Transcript of a public coin argument
struct Transcript {}

impl Transcript {
    /// Initialize a new transcript with the supplied label.
    fn new(label: &[u8]) -> Transcript {
        // Strobe init; meta-AD(label)
        unimplemented!();
    }

    /// Commit a prover's message to the transcript.
    fn commit(&mut self, label: &[u8], message: &[u8]) {
        // Strobe op: meta-AD(label || len(message)); AD(message)
        unimplemented!();
    }

    /// Fill the supplied buffer with the verifier's challenge bytes.
    fn challenge(&mut self, label: &[u8], challenge_bytes: &mut [u8]) {
        // Strobe op: meta-PRF(label || len(challenge_bytes)); PRF into challenge_bytes
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
