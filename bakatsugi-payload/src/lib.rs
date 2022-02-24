use std::ops::Range;

pub static PAYLOAD_ELF: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/payload.elf"));
include!(concat!(env!("OUT_DIR"), "/payload_constants.rs"));

static_assertions::assert_eq_size!(usize, u64, *const u8);

pub fn generate_payload(self_vmaddr: u64, dlopen_vmaddr: u64, cookie: &[u8; 16]) -> Vec<u8> {
    fn r(start: usize, size: usize) -> Range<usize> {
        Range {
            start,
            end: start + size,
        }
    }

    let range_self = r(PAYLOAD_OFFSET_SELF, 8);
    let range_dlopen = r(PAYLOAD_OFFSET_DLOPEN, 8);
    let range_cookie = r(PAYLOAD_OFFSET_COOKIE, 16);

    let actual_end = [&range_self, &range_dlopen, &range_cookie]
        .iter()
        .map(|r| r.end)
        .max()
        .unwrap();

    let mut payload = PAYLOAD_ELF[r(PAYLOAD_LOAD_P_OFFSET, PAYLOAD_LOAD_P_FILESZ)].to_owned();
    payload.resize(actual_end, 0);

    payload[range_self].copy_from_slice(&self_vmaddr.to_le_bytes());
    payload[range_dlopen].copy_from_slice(&dlopen_vmaddr.to_le_bytes());
    payload[range_cookie].copy_from_slice(cookie);
    payload
}

#[cfg(test)]
mod tests {
    use goblin::elf::Elf;

    use crate::{generate_payload, PAYLOAD_ELF};

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

    #[test]
    fn test_payload_fits_in_page() {
        let payload = generate_payload(0, 0, &[0; 16]);
        assert!(payload.len() <= 4096);
    }
}
