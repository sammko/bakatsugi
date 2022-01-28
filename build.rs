use anyhow::{Result, Context};
use const_gen::{const_declaration, CompileConst};
use std::{env, process::Command, path::Path, fs};

const PAYLOAD_ELF: &str = "payload.elf";
const PAYLOAD_CONSTS: &str = "payload_constants.rs";

fn generate_payload_consts(out_dir: &str) -> Result<()> {
    let path_elf = Path::new(&out_dir).join(PAYLOAD_ELF);
    let buffer = fs::read(path_elf)?;
    let elf = goblin::elf::Elf::parse(&buffer)?;
    
    let mut sym_p_ref = None;
    let mut sym_flagv = None;
    
    for sym in elf.syms.iter() {
        match elf.strtab.get_at(sym.st_name) {
            Some("p_ref") => sym_p_ref = Some(sym),
            Some("flagv") => sym_flagv = Some(sym),
            Some(_) | None => {},
        }
    }
    
    let sym_p_ref = sym_p_ref.context("Symbol p_ref missing")?;
    let sym_flagv = sym_flagv.context("Symbol flagv missing")?;
    
    let declarations = vec!{
        const_declaration!(PAYLOAD_OFFSET_FLAGV = sym_flagv.st_value),
        const_declaration!(PAYLOAD_OFFSET_P_REF = sym_p_ref.st_value),
    }.join("\n");
    
    let dest_path = Path::new(&out_dir).join(PAYLOAD_CONSTS);
    fs::write(&dest_path, declarations)?;
    Ok(())
}


fn build_payload(out_dir: &str) -> Result<()> {
    Command::new("nasm")
        .args(["src/payload.asm", "-f", "elf64", "-o"])
        .arg(format!("{}/payload.o", out_dir))
        .status()?;

    Command::new("ld")
        .arg(format!("{}/payload.o", out_dir))
        .args(["-T", "script.ld", "-o"])
        .arg(format!("{}/{}", out_dir, PAYLOAD_ELF))
        .status()?;
    
    Ok(())
}


fn main() -> Result<()> {
    let out_dir = env::var("OUT_DIR")?;

    build_payload(&out_dir)?;
    generate_payload_consts(&out_dir)?;

    cargo_emit::rerun_if_changed!("src/payload.asm");
    cargo_emit::rerun_if_changed!("script.ld");

    Ok(())
}