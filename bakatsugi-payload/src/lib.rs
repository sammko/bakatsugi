use std::ops::Range;

use anyhow::{bail, Context, Result};
use goblin::elf::{Elf, Sym};

pub static PAYLOAD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.elf"));
include!(concat!(env!("OUT_DIR"), "/payload_constants.rs"));

pub fn generate_payload(
    self_vmaddr: u64,
    dlopen_vmaddr: u64,
    cookie: &[u8; 16],
) -> Result<Vec<u8>> {
    let elf = Elf::parse(PAYLOAD_ELF)?;

    if elf.program_headers.len() != 1 {
        bail!("elf must contain exactly one phdr")
    }
    let phdr = elf.program_headers.get(0).unwrap();

    let mut sym_self = None;
    let mut sym_dlopen = None;
    let mut sym_cookie = None;

    for sym in elf.syms.iter() {
        match elf.strtab.get_at(sym.st_name) {
            Some("self") => sym_self = Some(sym),
            Some("dlopen") => sym_dlopen = Some(sym),
            Some("cookie") => sym_cookie = Some(sym),
            Some(_) | None => {}
        }
    }

    fn r(sym: &Sym, size: usize) -> Range<usize> {
        Range {
            start: sym.st_value as usize,
            end: sym.st_value as usize + size,
        }
    }

    let range_self = r(&sym_self.context("Symbol self missing")?, 8);
    let range_dlopen = r(&sym_dlopen.context("Symbol dlopen missing")?, 8);
    let range_cookie = r(&sym_cookie.context("Symbol cookie missing")?, 16);

    let actual_end = [&range_self, &range_dlopen, &range_cookie]
        .iter()
        .map(|r| r.end)
        .max()
        .unwrap();

    let mut payload = PAYLOAD_ELF[phdr.file_range()].to_owned();
    payload.resize(actual_end, 0);

    payload[range_self].copy_from_slice(&self_vmaddr.to_le_bytes());
    payload[range_dlopen].copy_from_slice(&dlopen_vmaddr.to_le_bytes());
    payload[range_cookie].copy_from_slice(cookie);

    Ok(payload)
}

#[cfg(test)]
mod tests {
    use goblin::elf::Elf;

    use crate::PAYLOAD_ELF;

    #[test]
    fn test_one_phdr() {
        let elf = Elf::parse(PAYLOAD_ELF).expect("Payload is not valid ELF");

        assert_eq!(
            1,
            elf.program_headers.len(),
            "Payload ELF must contain exactly one Phdr"
        );
    }

    #[test]
    fn test_entry_points() {
        let elf = Elf::parse(PAYLOAD_ELF).expect("Payload is not valid ELF");
        let mut sym_entry_syscall = None;
        let mut sym_entry_nonsyscall = None;
        for sym in elf.syms.iter() {
            match elf.strtab.get_at(sym.st_name) {
                Some("entry_syscall") => sym_entry_syscall = Some(sym),
                Some("entry_nonsyscall") => sym_entry_nonsyscall = Some(sym),
                Some(_) | None => {}
            }
        }
        let sym_entry_syscall = sym_entry_syscall.expect("Symbol entry_syscall missing");
        let sym_entry_nonsyscall = sym_entry_nonsyscall.expect("Symbol entry_nonsyscall missing");

        assert_eq!(
            0, sym_entry_syscall.st_value,
            "entry_syscall must be at offset 0"
        );
        assert_eq!(
            2, sym_entry_nonsyscall.st_value,
            "entry_nonsyscall must be at offset 2"
        );
    }
}
