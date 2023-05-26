# snitchrs
An eBPF-based program to keep track of the IPs to which your machine is connecting. Inspired by Little Snitch Mini.

## todo:
* connect: check if syn is there (e.g. connection start) record ip
* disconnect: check if flag is there then it's a disconnect
* 
- Connect{ ip }
- received { ip, buf_len }
- sent { ip, buf_len }
- closed { ip }

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain with the rust-src component: rustup toolchain install nightly --component rust-src
1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Build Userspace

```bash
cargo build
```

## Run

```bash
RUST_LOG=info cargo xtask run
```
