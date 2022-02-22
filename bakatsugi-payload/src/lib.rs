pub static PAYLOAD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.elf"));
include!(concat!(env!("OUT_DIR"), "/payload_constants.rs"));
