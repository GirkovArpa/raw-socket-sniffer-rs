# raw-socket-sniffer-rs

Rust port of this C repo:

https://github.com/nospaceships/raw-socket-sniffer

Progress halted due to a bug with the `winapi` crate:

```rust
let in_addr_S_un = winapi::shared::inaddr::in_addr_S_un {};
// cannot construct `in_addr_S_un` with struct literal syntax due to inaccessible fields 
```
