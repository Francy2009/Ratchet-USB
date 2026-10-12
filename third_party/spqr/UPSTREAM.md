# SPQR source provenance

This directory contains Signal Messenger's `SparsePostQuantumRatchet` crate,
version 1.6.0, copied from commit
`06959b4708f9b7b1e94d0f8cc835f3958c077e94` at
<https://github.com/signalapp/SparsePostQuantumRatchet>.

SPQR is licensed under `AGPL-3.0-only`; see `LICENSE`. Its copyright and
license notices in the source files are retained. The only local source change
is to `build.rs` and `Cargo.toml`: the build uses `protoc-bin-vendored` so it
does not depend on a system Protocol Buffers compiler.

`Cargo.lock` pins the dependencies, including the upstream test dependencies,
for standalone SPQR testing. The bridge has its own lockfile for the linked
application. Do not update this vendored crate without reviewing its license,
protocol behavior, and interoperability tests.
