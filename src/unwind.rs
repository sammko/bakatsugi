use std::fmt::Display;

use anyhow::Result;
use nix::unistd::Pid;
use unwind::{Accessors, AddressSpace, Byteorder, Cursor, PTraceState, RegNum};

#[derive(Debug, Clone)]
pub struct Symbol {
    name: String,
    offset: u64,
    address: u64,
    size: u64,
}

#[derive(Debug, Clone)]
pub struct Frame {
    sp: u64,
    ip: u64,
    is_signal: bool,
    symbol: Option<Symbol>,
}

impl Display for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.symbol {
            Some(ref sym) => write!(
                f,
                "{:#016x}: {:#016x} -{} {} ({:#016x}) + {:#x} (/{:#x})",
                self.sp,
                self.ip,
                if self.is_signal { " ! -" } else { "" },
                sym.name,
                sym.address,
                sym.offset,
                sym.size,
            ),
            None => write!(f, "{:#016x}: {:#016x} - ????", self.sp, self.ip),
        }
    }
}

pub fn unwind_ptrace(pid: Pid) -> Result<Vec<Frame>> {
    let accessors = Accessors::ptrace();
    let addr_space = AddressSpace::new(accessors, Byteorder::LITTLE_ENDIAN)?;
    let ptrace_state = PTraceState::new(pid.as_raw().try_into().unwrap())?;
    let mut cursor = Cursor::remote(&addr_space, &ptrace_state)?;
    let mut frames = Vec::new();
    loop {
        let ip = cursor.register(RegNum::IP)?;
        let sp = cursor.register(RegNum::SP)?;
        let sig = cursor.is_signal_frame()?;

        let sym = match (cursor.procedure_info(), cursor.procedure_name()) {
            (Ok(ref info), Ok(ref name)) if ip == info.start_ip() + name.offset() => Some(Symbol {
                name: name.name().to_string(),
                offset: name.offset(),
                address: info.start_ip(),
                size: info.end_ip() - info.start_ip(),
            }),
            _ => None,
        };

        frames.push(Frame {
            sp,
            ip,
            is_signal: sig,
            symbol: sym,
        });

        if !cursor.step()? {
            break;
        }
    }
    Ok(frames)
}
