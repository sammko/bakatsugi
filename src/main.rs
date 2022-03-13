use std::path::PathBuf;

use anyhow::Result;
use bakatsugi::do_inject;
use clap::Parser;
use nix::{libc::pid_t, unistd::Pid};

#[derive(Parser, Debug)]
#[clap(version)]
struct Args {
    /// Target process ID
    #[clap(short, long)]
    pid: pid_t,

    patchlib: PathBuf,

    #[clap(short, long)]
    debugelf: Option<PathBuf>,

    /// Close patch libraries after dlopen in target
    #[clap(long)]
    close_dso: bool,

    /// Close stage2 library after dlopen
    #[clap(long)]
    close_stage2: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    do_inject(
        Pid::from_raw(args.pid),
        &args.patchlib,
        args.debugelf.as_deref(),
        args.close_stage2,
        args.close_dso,
    )?;
    Ok(())
}
