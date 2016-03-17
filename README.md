This is a SNARK implementation using libsnark for the following:

``ZkPoK{ (R1, R2): H1 = sha256(R1) and H2 = sha256(R2) and R1 = R2 ^ X }``

Read: given `H1`, `H2`, and `X`, prove you know `R1` and `R2` such that `R1` is the preimage of `H1`,
`R2` is the preimage of `H2`, and `R1` is `R2 xor X`.

## performance

on my computer (Intel(R) Core(TM) i7-3770S CPU @ 3.10GHz):

* **key generation time**: 11.6551s
* **proof generation time**: 3.0884s
* **verification time**: 0.0262s
* **proof size**: 2294 bits
* **proving key size**: 102284136 bits
* **verifying key size**: 4586 bits
* **R1CS constraints**: 56101 (mostly sha256-related)

## howto

``./get-libsnark && make && ./test``

## anatomy

* `src/gadget.hpp` exposes the gadget, which is an abstraction of related constraint
and witness behavior in a circuit. This gadget uses other gadgets, creates its own
constraints, and exposes an interface for building input maps.

* `src/snark.hpp` exposes a loose wrapper around the constraint system and
key generation used by `test.cpp` to construct proofs and verify them as necessary.