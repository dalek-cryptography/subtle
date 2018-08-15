<img
 width="33%"
 align="right"
 src="https://upload.wikimedia.org/wikipedia/commons/7/79/Arthur-Pyle_The_Enchanter_Merlin.JPG"/>
 
## Merlin: composable proof transcripts for public-coin arguments of knowledge

Merlin is a [STROBE][strobe]-based construction of a proof transcript which
applies the Fiat-Shamir transform to an interactive public-coin
argument of knowledge.  This allows implementing protocols as if they
were interactive, committing messages to the proof transcript and
obtaining challenges bound to all previous messages.

In comparison to using a hash function directly, this design provides
support for:

* multi-round protocols with alternating commit and
challenge phases;

* natural domain separation, ensuring challenges are
bound to the statements to be proved;

* automatic message framing, preventing ambiguous encoding of commitment data;

* and protocol composition, by using a common transcript for multiple protocols.

**WARNING: This code is not yet suitable for deployment.**

## Design

Merlin is implemented in terms of [STROBE][strobe] operations.  Only a
subset of STROBE operations are used, because STROBE is intended as a
general-purpose framework for transport protocols, while Merlin is
intended only to provide proof transcripts.

Let `LE32(x)` be the little-endian byte encoding of the 32-bit integer
`x`.  Messages and challenges must be shorter than `2^32` bytes.

The STROBE operations to commit a prover's message `msg` are
```
meta-AD( label || LE32(msg.len()) );
AD( msg );
```
The STROBE operations to compute a verifier's challenge `chal` are
```
meta-AD( label || LE32(chal.len()) );
chal <- PRF();
```
Here `label` is a protocol-specific byte string that encodes
information about the message or challenge. (See the *Usage* section
below for more information).  The security properties of the
transcript are inherited from STROBE.

## Usage

Implementations of proof protocols using Merlin transcripts should
take an existing `Transcript` as a parameter, rather than initializing
a new one.  This ensures both that protocols are sequentially
composable — because they can be performed with a common `Transcript`
instance – and that they will be domain separated — because API
consumers must supply a customization string to create the
`Transcript`.

The Merlin API is a minimal, byte-oriented API aimed at maximum
flexibility.  However, an actual protocol makes use of typed data,
such as group elements, scalars, byte-strings, etc.  The recommended
way to accomplish this is to define a protocol-specific extension
trait which specifies how typed data is encoded into the transcript.
An example of this can be found in the `Transcript` documentation.

## License

This project is licensed under the MIT license; see `LICENSE.txt` for
details.

[strobe]: https://strobe.sourceforge.io/