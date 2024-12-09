# SGX Quote Verification in WASM

## Overview

This is a WASM package for performing remote attestations for SGX.
It depends on the crate: https://github.com/fleek-network/fleek-sgx

## Building the WASM package

1. Install `wasm-pack`:

```sh
cargo install wasm-pack
```

2. Build for NodeJS:

```sh
wasm-pack build --target nodejs
```
