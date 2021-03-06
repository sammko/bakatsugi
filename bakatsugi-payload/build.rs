#![feature(exit_status_error)]

use anyhow::{bail, Context, Result};
use const_gen::{const_declaration, CompileConst};
use std::{env, fs, path::Path, process::Command};

const PAYLOAD_ELF: &str = "payload.elf";
const PAYLOAD_CONSTS: &str = "payload_constants.rs";

fn generate_payload_consts(out_dir: &str) -> Result<()> {
    let path_elf = Path::new(&out_dir).join(PAYLOAD_ELF);
    let buffer = fs::read(path_elf)?;
    let elf = goblin::elf::Elf::parse(&buffer)?;

    if elf.program_headers.len() != 1 {
        bail!("elf must contain exactly one phdr")
    }
    let phdr = elf.program_headers.get(0).unwrap();

    let mut sym_self = None;
    let mut sym_dlopen = None;
    let mut sym_cookie = None;
    let mut sym_flagv = None;
    let mut sym_magic = None;
    let mut sym_close_stage2 = None;

    for sym in elf.syms.iter() {
        match elf.strtab.get_at(sym.st_name) {
            Some("self") => sym_self = Some(sym),
            Some("dlopen") => sym_dlopen = Some(sym),
            Some("cookie") => sym_cookie = Some(sym),
            Some("flagv") => sym_flagv = Some(sym),
            Some("magic") => sym_magic = Some(sym),
            Some("close_stage2") => sym_close_stage2 = Some(sym),
            Some(_) | None => {}
        }
    }

    let sym_self = sym_self.context("Symbol self missing")?;
    let sym_dlopen = sym_dlopen.context("Symbol dlopen missing")?;
    let sym_cookie = sym_cookie.context("Symbol cookie missing")?;
    let sym_flagv = sym_flagv.context("Symbol flagv missing")?;
    let sym_magic = sym_magic.context("Symbol magic missing")?;
    let sym_close_stage2 = sym_close_stage2.context("Symbol close_stage2 missing")?;

    let magic_offset = sym_magic.st_value;
    let magic_section = elf
        .section_headers
        .get(sym_magic.st_shndx)
        .context("section containing magic missing")?;
    let magic_file_offset =
        (magic_offset - magic_section.sh_addr + magic_section.sh_offset) as usize;
    let magic_val = u64::from_le_bytes(
        buffer[magic_file_offset..magic_file_offset + 8]
            .try_into()
            .unwrap(),
    );

    let declarations = vec![
        const_declaration!(pub PAYLOAD_OFFSET_SELF = (sym_self.st_value as usize)),
        const_declaration!(pub PAYLOAD_OFFSET_DLOPEN = (sym_dlopen.st_value as usize)),
        const_declaration!(pub PAYLOAD_OFFSET_FLAGV = (sym_flagv.st_value as usize)),
        const_declaration!(pub PAYLOAD_OFFSET_COOKIE = (sym_cookie.st_value as usize)),
        const_declaration!(pub PAYLOAD_OFFSET_CLOSE_STAGE2 = (sym_close_stage2.st_value as usize)),
        const_declaration!(PAYLOAD_LOAD_P_OFFSET = (phdr.p_offset as usize)),
        const_declaration!(PAYLOAD_LOAD_P_FILESZ = (phdr.p_filesz as usize)),
        const_declaration!(pub PAYLOAD_MAGIC = magic_val),
    ]
    .join("\n");

    let dest_path = Path::new(&out_dir).join(PAYLOAD_CONSTS);
    fs::write(&dest_path, declarations)?;
    Ok(())
}

trait CommandExt {
    fn status_exit_ok(&mut self) -> Result<()>;
}

impl CommandExt for Command {
    fn status_exit_ok(&mut self) -> Result<()> {
        let program = self
            .get_program()
            .to_str()
            .expect("program name not utf-8")
            .to_owned();
        self.status()
            .context(format!("Failed to execute {}", program))?
            .exit_ok()
            .context(format!("{} did not exit successfully", program))?;
        Ok(())
    }
}

fn build_payload(out_dir: &str, debug: bool) -> Result<()> {
    Command::new("nasm")
        .args(["src/payload_stub.asm", "-f", "elf64", "-o"])
        .arg(format!("{}/payload_stub.o", out_dir))
        .status_exit_ok()?;

    let mut cc_flags = vec![
        "-Os",
        "-c",
        "-fno-asynchronous-unwind-tables",
        "-pedantic",
        "-nostdlib",
        "-Wall",
        "-Wextra",
        "-fPIC",
        "-fno-stack-protector",
    ];
    if debug {
        cc_flags.push("-DDBG");
    }
    Command::new("gcc")
        .args(&cc_flags)
        .arg("-o")
        .arg(format!("{}/payload.o", out_dir))
        .arg("src/payload.c")
        .status_exit_ok()?;

    Command::new("ld")
        .arg(format!("{}/payload_stub.o", out_dir))
        .arg(format!("{}/payload.o", out_dir))
        .args(["-T", "script.ld", "-o"])
        .arg(format!("{}/{}", out_dir, PAYLOAD_ELF))
        .status_exit_ok()?;

    Ok(())
}

fn main() -> Result<()> {
    let out_dir = env::var("OUT_DIR")?;
    let debug = env::var("DEBUG")? == "true";

    build_payload(&out_dir, debug)?;
    generate_payload_consts(&out_dir)?;

    cargo_emit::rerun_if_changed!("src/payload.c");
    cargo_emit::rerun_if_changed!("src/payload_stub.asm");
    cargo_emit::rerun_if_changed!("script.ld");

    Ok(())
}
