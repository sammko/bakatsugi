use std::{fs, path::PathBuf};

use anyhow::{bail, Context, Result};
use goblin::elf::Elf;
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
    let libc = fs::read(get_mapfile(pid, map.start(), map.size()))
        .context("Failed to load libc elf from /proc/N/map_files")?;
    let elf = Elf::parse(&libc).context("Failed to parse libc image as elf")?;

    let dynstrtab = elf.dynstrtab;
    for sym in elf.dynsyms.iter() {
        let name = dynstrtab.get_at(sym.st_name);
        // glibc 2.34 removes __libc_dlopen_mode but instead
        // libdl is merged in, including normal dlopen. Same signature,
        // don't care which one it is.
        if let Some("__libc_dlopen_mode" | "dlopen") = name {
            return Ok(sym.st_value - map.offset as u64 + map.start() as u64);
        }
    }
    bail!("Could not find dlopen");
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
