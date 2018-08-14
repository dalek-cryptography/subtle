<img
 width="33%"
 align="right"
 src="https://upload.wikimedia.org/wikipedia/commons/7/79/Arthur-Pyle_The_Enchanter_Merlin.JPG"/>
 
## Merlin: composable proof transcripts for public-coin arguments of knowledge

Merlin is a STROBE-based construction of a proof transcript which
applies the Fiat-Shamir transform to an interactive public-coin
argument of knowledge.  This allows implementing arguments as if they
were interactive, committing messages to the proof transcript and
obtaining challenges bound to all previous messages.

In comparison to using a hash function directly, this design provides
support for:

* multi-round arguments with alternating commit and
challenge phases;

* natural domain separation, ensuring challenges are
bound to the statements to be proved;

* automatic message framing, preventing ambiguous encoding of commitment data;

* and argument composition, by using a common transcript for multiple arguments.

## WARNING

This code is not yet suitable for deployment.


