#![feature(unix_socket_abstract)]
#![feature(c_size_t)]
#![feature(let_else)]
#![feature(unix_socket_ancillary_data)]

mod trampoline;

use bakatsugi_payload::{PAYLOAD_MAGIC, PAYLOAD_OFFSET_COOKIE, PAYLOAD_OFFSET_FLAGV};
use bakatsugi_protocol::{MessageItoT, MessageTtoI, Net};
use core::slice;
use libloading::{Library, Symbol};
use proc_maps::MapRange;
use std::{
    arch::asm,
    collections::HashMap,
    fs,
    io::IoSliceMut,
    mem,
    os::unix::net::{
        AncillaryData::{ScmCredentials, ScmRights},
        SocketAddr, SocketAncillary, UnixStream,
    },
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use ctor::ctor;
use goblin::{
    elf::Elf,
    elf64::reloc::{R_X86_64_GLOB_DAT, R_X86_64_JUMP_SLOT},
};
use nix::{
    libc::{c_void, getauxval, AT_ENTRY},
    sys::mman::{mprotect, ProtFlags},
    unistd::{close, getpid},
};

use crate::trampoline::{make_large_trampoline, TrampolineAllocator};

#[ctor]
fn _init() {
    if cfg!(test) {
        // Putting a #[cfg(not(test))] on the whole function causes unused code warnings.
        return;
    }
    match init() {
        Ok(_) => {}
        Err(e) => eprintln!("=== PATCH FAILED ===\n{:?}\n====================", e),
    }
}

fn get_stage1_vma(maps: &[MapRange]) -> Result<usize> {
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
            if *p_rsp == PAYLOAD_MAGIC {
                // Clobber magic just in case for future patches
                *p_rsp = 0;
                let self_vmaddr = *p_rsp.offset(1);
                return Ok(self_vmaddr as usize);
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

unsafe fn get_payload_data(stage1_vma: usize) -> Result<PayloadData> {
    let cookie = slice::from_raw_parts((stage1_vma + PAYLOAD_OFFSET_COOKIE) as *const u8, 16);
    let flagv = *((stage1_vma + PAYLOAD_OFFSET_FLAGV) as *const u8);
    Ok(PayloadData {
        cookie: cookie.try_into()?,
        was_syscall: flagv > 0,
    })
}

fn find_load_bias(self_exe: &Elf) -> Result<u64> {
    // Watch out, kernel doesn't populate the AT_PHDR auxv correctly.
    // https://bugzilla.kernel.org/show_bug.cgi?id=197921
    // We can use the AT_ENTRY also, the calculation is even simpler.

    let entry_addr = self_exe.header.e_entry;
    let entry_vma = match unsafe { getauxval(AT_ENTRY) } {
        0 => bail!("getauxval(AT_ENTRY) returned 0"),
        x => x,
    };

    Ok(entry_vma - entry_addr)
}

#[allow(dead_code)]
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

    let load_bias = find_load_bias(&elf)?;
    let got_entry = load_bias + offset;

    eprintln!("base: {:x}", load_bias);
    eprintln!("GOT entry at vma {:x}", got_entry);
    eprintln!("fake at {:x}", fake_fun);

    unsafe {
        // bypass RELRO
        mprotect(
            (got_entry & 0xfffffffffffff000) as *mut c_void,
            4096,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        )?;
        *((load_bias + offset) as *mut usize) =
            fake_fun + symbol_reloc.r_addend.unwrap_or(0) as usize;
    }

    Ok(())
}

enum PatchOwnStrategy<'a> {
    LargeTrampoline,
    SmallTrampoline(&'a [MapRange], &'a mut Option<TrampolineAllocator>),
}

fn patch_own_fn(
    strategy: PatchOwnStrategy,
    name: &str,
    replacement_fn: usize,
    debug_elf: &str,
) -> Result<()> {
    let data = fs::read(debug_elf)?;
    let elf = Elf::parse(&data)?;

    let target_function = elf
        .syms
        .iter()
        .find(|s| elf.strtab.get_at(s.st_name) == Some(name))
        .context(
            "Could not find symbol for target function. Does your binary have debug symbols?",
        )?;

    let load_bias = find_load_bias(&elf)?;
    let actual_target = load_bias + target_function.st_value;
    eprintln!("target at: {:x}", actual_target);
    eprintln!("replacement at: {:x}", replacement_fn);

    let trampoline = match strategy {
        PatchOwnStrategy::LargeTrampoline => make_large_trampoline(replacement_fn as u64),
        PatchOwnStrategy::SmallTrampoline(maps, alloc) => {
            if alloc.is_none() {
                alloc.replace(TrampolineAllocator::new(get_closest_free_page(
                    maps,
                    actual_target as usize,
                ))?);
            }
            alloc
                .as_mut()
                .unwrap()
                .write_next_trampoline(actual_target, replacement_fn as u64)?
        }
    };

    eprintln!("trampoline: {:x?}", trampoline);

    unsafe {
        // TODO we need to watch out for page borders and functions shorter than the trampoline.
        mprotect(
            (actual_target & 0xfffffffffffff000) as *mut c_void,
            4096,
            ProtFlags::PROT_READ | ProtFlags::PROT_WRITE | ProtFlags::PROT_EXEC,
        )?;
        let tgt_buf = slice::from_raw_parts_mut(actual_target as *mut u8, trampoline.len());
        tgt_buf.copy_from_slice(&trampoline);
        // TODO mprotect back
    }

    Ok(())
}

fn get_closest_free_page(maps: &[MapRange], target: usize) -> usize {
    //find range containing target
    match maps
        .iter()
        .position(|r| r.start() <= target && r.start() + r.size() > target)
    {
        None => target & 0xfffffffffffff000,
        Some(i) => {
            let mut candidate_right = maps[maps.len() - 1].start() + maps[maps.len() - 1].size();
            for j in i..maps.len() - 1 {
                if maps[j].start() + maps[j].size() == maps[j + 1].start() {
                    continue;
                } else {
                    candidate_right = maps[j].start() + maps[j].size();
                    break;
                }
            }

            let mut candidate_left = maps[0].start() - 4096;
            for j in (1..i + 1).rev() {
                if maps[j - 1].start() + maps[j - 1].size() == maps[j].start() {
                    continue;
                } else {
                    candidate_left = maps[j].start() - 4096;
                    break;
                }
            }

            if candidate_right - target < target - candidate_left {
                candidate_right
            } else {
                candidate_left
            }
        }
    }
}

fn receive_fd(sock: &UnixStream) -> Result<i32> {
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    sock.recv_vectored_with_ancillary(&mut [IoSliceMut::new(&mut [0])], &mut ancillary)?;
    let mut rfd = None;
    for message in ancillary.messages() {
        match message {
            Ok(data) => match data {
                ScmRights(rights) => {
                    for fd in rights {
                        eprintln!("Got fd: {}", fd);
                        rfd = Some(fd);
                    }
                }
                ScmCredentials(_) => {
                    eprintln!("Ignore ScmCredentials message");
                }
            },
            Err(e) => {
                eprintln!("Ignore: {:?}", e);
            }
        }
    }
    rfd.context("Did not receive fd")
}

fn init() -> Result<()> {
    let pid = getpid();
    let mut maps = proc_maps::get_process_maps(pid.as_raw())?;
    maps.sort_by_key(|m| m.start());
    let stage1_vma = get_stage1_vma(&maps)?;
    let data = unsafe { get_payload_data(stage1_vma)? };

    println!("{:?}", data);

    let addr = SocketAddr::from_abstract_namespace(&data.cookie)?;
    let mut sock = UnixStream::connect_addr(&addr)?;

    let mut dso_map = HashMap::new();
    let mut debug_elf_path: String = "/proc/self/exe".to_string();

    let mut trampoline_allocator: Option<TrampolineAllocator> = None;

    loop {
        let msg_in = MessageItoT::recv(&mut sock)?;
        match msg_in {
            MessageItoT::Ping(x) => {
                MessageTtoI::Pong(x).send(&mut sock)?;
            }
            MessageItoT::Quit => break,
            MessageItoT::OpenDSO(id, path) => {
                eprintln!("Opening patch lib: {}", path.to_string_lossy());
                let lib = unsafe { Library::new(path) }.context("Failed to open library")?;
                dso_map.insert(id, lib);
                MessageTtoI::Ok.send(&mut sock)?;
            }
            MessageItoT::RecvDSO(id, should_close) => {
                let fd = receive_fd(&sock)?;
                let path = PathBuf::from(format!("/proc/self/fd/{}", fd));
                eprintln!("Opening patch lib: {}", path.to_string_lossy());
                let lib = unsafe { Library::new(path) }.context("Failed to open library")?;
                dso_map.insert(id, lib);
                if should_close {
                    close(fd)?;
                }
                MessageTtoI::Ok.send(&mut sock)?;
            }
            MessageItoT::PatchLib(fun, id, replacement) => {
                let Some(lib) = dso_map.get(&id) else { bail!("Got bad lib id from injector") };
                let fptr: Symbol<*mut c_void> = unsafe { lib.get(replacement.as_bytes()) }
                    .context("Failed to lookup symbol")?;
                patch_reloc(&fun, unsafe { fptr.into_raw() }.into_raw() as usize)?;
                MessageTtoI::Ok.send(&mut sock)?;
            }
            MessageItoT::PatchOwn(fun, id, replacement, kind) => {
                let Some(lib) = dso_map.get(&id) else { bail! ("Got bad lib id from injector") };
                let fptr: Symbol<*mut c_void> = unsafe { lib.get(replacement.as_bytes()) }
                    .context("Failed to lookup symbol")?;

                let strategy = match kind {
                    bakatsugi_protocol::TrampolineKind::Indirect5 => {
                        PatchOwnStrategy::SmallTrampoline(&maps, &mut trampoline_allocator)
                    }
                    bakatsugi_protocol::TrampolineKind::Absolute12 => {
                        PatchOwnStrategy::LargeTrampoline
                    }
                };

                patch_own_fn(
                    strategy,
                    &fun,
                    unsafe { fptr.into_raw() }.into_raw() as usize,
                    &debug_elf_path,
                )?;
                MessageTtoI::Ok.send(&mut sock)?;
            }
            MessageItoT::RecvDebugElf => {
                let fd = receive_fd(&sock)?;
                debug_elf_path = format!("/proc/self/fd/{}", fd);
                MessageTtoI::Ok.send(&mut sock)?;
            }
        }
    }

    // Forget the entire hashmap of libraries, this prevents them from
    // getting dlclose'd by the Drop impl.
    mem::forget(dso_map);

    Ok(())
}
