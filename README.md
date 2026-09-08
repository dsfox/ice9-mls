# ice9-mls

The end-to-end encryption core of [ice9](https://ice9.app), built on MLS
(RFC 9420) via [OpenMLS](https://github.com/openmls/openmls).

One Rust crate for both the iOS and Android clients. It compiles to a static
library with a small C ABI (`src/ffi.rs`), and the clients call it over that
boundary. It handles the MLS groups, the recovery phrase and the keys it stands
for, and the device state that survives a restart. Message content is encrypted
here on the device; the ice9 server only ever carries ciphertext it cannot read.

This is the encryption source of the ice9 apps, published on its own so the
cryptography the apps ship is available in source.

## Build

    cargo test             # the crate's own tests
    cargo build --release  # the static library (libmls.a)

## License

MIT — see [LICENSE](LICENSE).
