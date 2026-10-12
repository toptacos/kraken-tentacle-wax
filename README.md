# wax

Sign brine/keeps *bundles*. Prefer `minisign` and `age` when installed.

Without those binaries, `sign`/`verify` use a local HMAC fixture (`wax-hmac`) so CI can still fail a tamper. That fixture is not Ed25519 and is not minisign-compatible.

Does not store the keeps AES key. Does not write into `~/.kraken/keys`.
