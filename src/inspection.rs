use std::{
    fs::{self, File},
    io::{ErrorKind, Read},
    path::PathBuf,
};

use anyhow::{anyhow, bail, Context, Result};
use goblin::{elf::Elf, elf64::program_header::PT_LOAD};
use nix::unistd::Pid;
use proc_maps::MapRange;
use regex::Regex;

fn get_libc_text_maprange(pid: Pid) -> Result<MapRange> {
    let re = Regex::new(r"^libc(-[0-9.]+)?\.so[0-9.]*$").unwrap();
    for map in proc_maps::get_process_maps(pid.as_raw())
        .context("Failed to retrieve memory map of target")?
    {
        // ASSUMPTION: libc contains only one executable mapping,
        // corresponding to the LOAD phdr containing .text.
        if !map.is_exec() {
            continue;
        }
        if let Some(basename) = map.filename().and_then(|f| f.file_name()) {
            match basename.to_str() {
                Some(s) => {
                    if re.is_match(s) {
                        return Ok(map);
                    }
                }
                None => continue,
            }
        }
    }
    bail!("No mapping matches known libc names")
}

fn get_mapfile(pid: Pid, start: usize, size: usize) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/map_files/{:x}-{:x}",
        pid.as_raw(),
        start,
        start + size
    ))
}

pub fn get_dlopen_vmaddr(pid: Pid) -> Result<u64> {
    let map = get_libc_text_maprange(pid).context("Failed to find libc .text mapping")?;

    let libc_mapfile = get_mapfile(pid, map.start(), map.size());
    let libc = match fs::read(&libc_mapfile) {
        Ok(f) => f,
        Err(e) => match e.kind() {
            ErrorKind::PermissionDenied => {
                let filename = map.filename().context("MapRange does not have filename")?;
                eprintln!(
                    "Failed to open libc from {:?}, falling back to {:?}. CAP_SYS_ADMIN is required to access map_files, despite having permission to ptrace the target. {}",
                    &libc_mapfile,
                    filename,
                    e
                );
                fs::read(filename).context(format!("Could not open libc from {:?}", filename))?
            }
            _ => return Err(anyhow!(e)),
        },
    };

    let elf = Elf::parse(&libc).context("Failed to parse libc image as elf")?;

    let exec_phdr = {
        let mut v = None;
        for phdr in elf.program_headers {
            if phdr.p_type == PT_LOAD
                && phdr.is_executable()
                && phdr.p_offset as usize == map.offset
            {
                v = Some(phdr);
                break;
            }
        }
        v.context("Could not find matching exec phdr")?
    };
    eprintln!("Found matching libc phdr: {:?}", &exec_phdr);

    let dynstrtab = elf.dynstrtab;
    for sym in elf.dynsyms.iter() {
        let name = dynstrtab.get_at(sym.st_name);
        // glibc 2.34 removes __libc_dlopen_mode but instead
        // libdl is merged in, including normal dlopen. Same signature,
        // don't care which one it is.
        if matches!(name, Some("__libc_dlopen_mode" | "dlopen")) {
            return Ok(sym.st_value - exec_phdr.p_vaddr + map.start() as u64);
        }
    }
    bail!("Could not find dlopen");
}

fn load_target_exe(pid: Pid) -> Result<Vec<u8>> {
    let mut buf = vec![];
    File::open(format!("/proc/{}/exe", pid.as_raw()))?.read_to_end(&mut buf)?;
    Ok(buf)
}

#[derive(Debug)]
pub struct SymOwnFunction {
    name: String,
}

impl SymOwnFunction {
    pub fn get_name(&self) -> &str {
        &self.name
    }
}

pub fn get_symbols_own(pid: Pid, keep_crt: bool) -> Result<Vec<SymOwnFunction>> {
    let exe = load_target_exe(pid)?;
    let elf = Elf::parse(&exe)?;

    fn is_crt(s: &SymOwnFunction) -> bool {
        static KNOWN_CRT: &[&str] = &[
            "deregister_tm_clones",
            "register_tm_clones",
            "__do_global_dtors_aux",
            "frame_dummy",
            "_fini",
            "_start",
            "_init",
        ];
        KNOWN_CRT.contains(&&s.name[..])
    }

    let symbols = elf
        .syms
        .iter()
        .filter(|s| s.is_function() && !s.is_import())
        .map(|s| {
            elf.strtab
                .get_at(s.st_name)
                .map(|name| SymOwnFunction {
                    name: name.to_string(),
                })
                .context("Symbol with invalid st_name")
        })
        .filter(|re| match re {
            Ok(s) => keep_crt || !is_crt(s),
            Err(_) => true,
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(symbols)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapfile() {
        assert_eq!(
            get_mapfile(
                Pid::from_raw(1),
                0x7fcb02618000,
                0x7fcb02621000 - 0x7fcb02618000
            ),
            PathBuf::from("/proc/1/map_files/7fcb02618000-7fcb02621000")
        );
        assert_eq!(
            get_mapfile(Pid::from_raw(123), 4096, 4096),
            PathBuf::from("/proc/123/map_files/1000-2000")
        );
    }
}
