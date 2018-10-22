
# mix_link
[![](https://travis-ci.org/david415/mix_link.png?branch=master)](https://www.travis-ci.org/david415/mix_link) [![](https://img.shields.io/crates/v/mix_link.svg)](https://crates.io/crates/mix_link) [![](https://docs.rs/mix_link/badge.svg)](https://docs.rs/mix_link/)

This crate provides a Noise Protocol Framework based cryptographic
link layer wire protocol for constructing mix networks.


# warning

This code has not been formally audited by a cryptographer. It
therefore should not be considered safe or correct. Use it at your own
risk!


# details

This wire protocol is designed to construct mix networks.
You can read the design specification document here:

* https://github.com/katzenpost/docs/blob/master/specs/wire-protocol.rst

This cryptographic link layer protocol uses ``Noise_XX_25519_ChaChaPoly_BLAKE2b``
which you can read about here in the Noise Protocol specification document:

* http://noiseprotocol.org/noise.html

This differ's from Yawning's design in that I am not using the
post-quantum via New Hope Simple for hybrid forward secrecy of the XX
handshake pattern. In order to make this possible we would first need
an implementation of New Hope Simple in rust and then to modify snow,
the rust noise library such that it would have HFS mode, that is the
PQ hybrid forward secrecy mode via New Hope Simple.


# Usage

To import `mix_link`, add the following to the dependencies section of
your project's `Cargo.toml`:
```toml
mix_link = "^0.0.2"
```
Then import the crate as:
```rust,no_run
extern crate mix_link;
```


# acknowledgments

Thanks to Yawning Angel for the design of this wire protocol.


# license

GNU AFFERO GENERAL PUBLIC LICENSE