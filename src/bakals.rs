use anyhow::Result;
use bakatsugi::inspection::{get_symbols_lib, get_symbols_own, InspectionTarget};
use clap::{ArgEnum, Parser};
use nix::{libc::pid_t, unistd::Pid};

#[derive(Debug, Clone, ArgEnum)]
enum SymbolKind {
    Own,
    Lib,
}

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(arg_enum)]
    kind: SymbolKind,

    #[clap(short, long)]
    pid: pid_t,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let pid = Pid::from_raw(args.pid);
    match args.kind {
        SymbolKind::Own => {
            for s in get_symbols_own(InspectionTarget::Process(pid), false)? {
                println!("{}", s.get_name());
            }
        }
        SymbolKind::Lib => {
            for s in get_symbols_lib(InspectionTarget::Process(pid))? {
                println!("{}", s.get_name());
            }
        }
    }
    Ok(())
}
