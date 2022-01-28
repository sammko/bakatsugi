use core::slice;
use std::arch::asm;

use anyhow::{bail, Context, Result};
use ctor::ctor;
use nix::unistd::getpid;
use proc_maps::MapRange;

include!(concat!(env!("OUT_DIR"), "/payload_constants.rs"));
const MAGIC: u64 = 0x68637450616b6142;

#[ctor]
fn _init() {
    match init() {
        Ok(_) => {}
        Err(e) => eprintln!("=== PATCH FAILED: {} ===", e),
    }
}

#[no_mangle]
fn get_self(maps: &[MapRange]) -> Result<u64> {
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
        let p_rsp = rsp_aligned as *const u64;
        unsafe {
            if *p_rsp == MAGIC {
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
    pub was_syscall: bool
}

fn get_payload_data(self_vmaddr: u64) -> Result<PayloadData> {
    unsafe {
        let p_ref = slice::from_raw_parts((self_vmaddr + PAYLOAD_OFFSET_P_REF) as *const u8, 16);
        let flagv = *((self_vmaddr + PAYLOAD_OFFSET_FLAGV) as *const u8);
        return Ok(PayloadData {
            cookie: p_ref.try_into()?,
            was_syscall: flagv > 0
        })
    }
}

fn init() -> Result<()> {
    let pid = getpid();
    let maps = proc_maps::get_process_maps(pid.as_raw())?;
    let self_vmaddr = get_self(&maps)?;
    let data = get_payload_data(self_vmaddr)?;

    println!("{:?}", data);

    Ok(())
}
