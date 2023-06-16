# snitchrs
A simple eBPF-based program to keep track of the IPs to which your machine is connecting. Inspired by Little Snitch Mini.
## Demo:
The window below is the freshly started ui running. In the terminal at the top I'm using curl to connect to a bunch of websites and they get displayed on the map.
The ip is showed in the tooltip:


## eBPF:
The eBPF prints the following events to stdout for ipv4:
* `<direction>_connect remote_ip:remote_port :local_port`: emitted on every tcp `sin` packet.
* `<direction>_disconnect remote_ip:remote_port :local_port`: emitted on every tcp `fin` packet
* `<direction>_traffic remote_ip:remote_port :local_port transfered_bytes`: emitted on every tcp packet that is not sin nor fin.
* `syscall_<connect|accept> remote_ip:remote_port pid`: emitted on every syscall call to `connect` and `accept`.

## UI:
It's implemented in python with qt, will read from stdin the events and visualize them on a map. 
For now, it's only using the `connect` and `disconnect` events.

## Run:
To run it, just call run.sh.

---

## Dev
### Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
2. Install a rust nightly toolchain with the rust-src component: rustup toolchain install nightly --component rust-src
3. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

To perform a release build, you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

### Build Userspace

```bash
cargo build
```

### Run 

```bash
RUST_LOG=info cargo xtask run
```


