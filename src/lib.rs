#![feature(unix_socket_abstract)]
#![feature(c_size_t)]

use core::slice;
use std::{
    arch::asm,
    env, fs,
    io::Write,
    os::{
        raw::{c_size_t, c_ssize_t},
        unix::net::{SocketAddr, UnixStream},
    },
    ptr::slice_from_raw_parts,
};

use anyhow::{bail, Context, Result};
use ctor::ctor;
use goblin::{
    elf::Elf,
    elf64::reloc::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT},
};
use nix::{
    libc::{self, c_int, c_void, getauxval, AT_PHDR},
    sys::mman::{mprotect, ProtFlags},
    unistd::getpid,
};
use rand::{prelude::SliceRandom, thread_rng};

include!(concat!(env!("OUT_DIR"), "/payload_constants.rs"));
const MAGIC: u64 = 0x68637450616b6142;

#[ctor]
fn _init() {
    match init() {
        Ok(_) => {}
        Err(e) => eprintln!("=== PATCH FAILED: {} ===", e),
    }
}

fn get_stage1_vma() -> Result<u64> {
    let pid = getpid();
    let maps = proc_maps::get_process_maps(pid.as_raw())?;

    let rsp: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) rsp);
    }

    let stack_mapping = maps
        .iter()
        .find(|&r| r.start() <= rsp as usize && (rsp as usize) <= r.start() + r.size())
        .context("Could not find stack mapping")?;
    eprintln!("stack_mapping: {:?}", stack_mapping);
    eprintln!("rsp: 0x{:x}", rsp);

    let mut rsp_aligned = (rsp + 4096) & 0xfffffffffffff000;
    while rsp_aligned < (stack_mapping.start() + stack_mapping.size()) as u64 {
        eprintln!("Checking at 0x{:x}", rsp_aligned);
        let p_rsp = rsp_aligned as *mut u64;
        unsafe {
            if *p_rsp == MAGIC {
                // Clobber magic just in case for future patches
                *p_rsp = 0;
                let self_vmaddr = *p_rsp.offset(1);
                return Ok(self_vmaddr);
            }
        }
        rsp_aligned += 0x1000;
    }
    bail!("Could not find payload mapping");
}

#[derive(Debug)]
pub struct PayloadData {
    pub cookie: [u8; 16],
    pub was_syscall: bool,
}

unsafe fn get_payload_data(stage1_vma: u64) -> Result<PayloadData> {
    let cookie = slice::from_raw_parts((stage1_vma + PAYLOAD_OFFSET_COOKIE) as *const u8, 16);
    let flagv = *((stage1_vma + PAYLOAD_OFFSET_FLAGV) as *const u8);
    Ok(PayloadData {
        cookie: cookie.try_into()?,
        was_syscall: flagv > 0,
    })
}

fn patch_reloc(name: &str, fake_fun: usize) -> Result<()> {
    // hmm maybe we should be doing this from the outside instead
    let data = fs::read("/proc/self/exe")?;
    let elf = Elf::parse(&data)?;

    // Find relocation for given symbol
    let symbol_reloc = elf
        .dynrelas
        .iter()
        .chain(elf.pltrelocs.iter())
        .find(|r| {
            elf.dynsyms
                .get(r.r_sym)
                .and_then(|s| elf.dynstrtab.get_at(s.st_name))
                == Some(name)
        })
        .context(format!("Could not find reloc for {}", name))?;

    if !(symbol_reloc.r_type == R_X86_64_GLOB_DAT || symbol_reloc.r_type == R_X86_64_JUMP_SLOT) {
        bail!("Unsupported relocation {}", symbol_reloc.r_type)
    }

    let offset = symbol_reloc.r_offset;

    // Find PHDR containing the relocation's target
    let phdr = elf
        .program_headers
        .iter()
        .find(|&phdr| phdr.vm_range().contains(&(offset as usize)))
        .context("Could not find phdr containing reloc offset")?;

    // TODO is this correct?
    let phdr_vma = unsafe { getauxval(AT_PHDR) };
    let x = phdr_vma - elf.header.e_phoff;
    let got_entry = x + offset;

    eprintln!("phdr is: {:?}", phdr);
    eprintln!("base: {:x}", x);
    eprintln!("GOT entry at vma {:x}", x + offset);
    eprintln!("fake at {:x}", fake_fun);

    unsafe {
        // bypass RELRO
        mprotect(
            (got_entry & 0xfffffffffffff000) as *mut c_void,
            4096,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )?;
        *((x + offset) as *mut usize) = fake_fun + symbol_reloc.r_addend.unwrap_or(0) as usize;
    }

    Ok(())
}

pub extern "C" fn fakewrite(fildes: c_int, buf: *const c_void, nbyte: c_size_t) -> c_ssize_t {
    if nbyte > 0 {
        let inp = unsafe { &*slice_from_raw_parts(buf as *const u8, nbyte) };
        let mut tmp = inp.to_owned();
        if inp[nbyte - 1] == b'\n' {
            tmp[..nbyte - 1].shuffle(&mut thread_rng());
        } else {
            tmp.shuffle(&mut thread_rng());
        }
        unsafe { libc::write(fildes, tmp.as_ptr() as *const c_void, nbyte) }
    } else {
        0
    }
}

fn init() -> Result<()> {
    let stage1_vma = get_stage1_vma()?;
    let data = unsafe { get_payload_data(stage1_vma)? };

    println!("{:?}", data);

    let addr = SocketAddr::from_abstract_namespace(&data.cookie)?;
    let mut sock = UnixStream::connect_addr(&addr)?;
    sock.write_all(b"Hello")?;

    patch_reloc("write", fakewrite as usize)?;

    Ok(())
}
