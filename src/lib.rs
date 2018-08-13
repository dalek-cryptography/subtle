
extern crate byteorder;
extern crate keccak;

mod strobe;

use strobe::Strobe128;

fn encode_usize(x: usize) -> [u8; 4] {
    use byteorder::{LittleEndian, ByteOrder};

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
            strobe: Strobe128::new(label)
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
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
