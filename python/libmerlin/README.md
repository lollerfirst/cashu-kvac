## A single-file C implementation of Merlin transcripts.

When finished, this repository will contain a portable single-file C
implementation of the Merlin transcript and RNG API for use by C libraries.

More information about Merlin can be found in the documentation for the [Rust
implementation][merlin_rs].

The build system for this library is Cargo and the test suite is written in
Rust, calling the C implementation via FFI and performing conformance tests
with the Rust implementation.

The intended way for a C project to use this library is to add this repo as a
git submodule under e.g., `contrib/merlin`, then add
`contrib/merlin/src/merlin.c` and `contrib/merlin/src/merlin.h` to that
project's build system, as appropriate.  The Rust test suite and Cargo
configuration is thus ignored by the library consumers.

This implementation is derived from David Leon Gil's `keccak-tiny`.

[merlin_rs]: https://doc.dalek.rs/merlin
