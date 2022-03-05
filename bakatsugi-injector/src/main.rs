use std::path::PathBuf;

use anyhow::Result;
use bakatsugi_injector::do_inject;
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
}

fn main() -> Result<()> {
    let args = Args::parse();

    do_inject(
        Pid::from_raw(args.pid),
        &args.patchlib,
        args.debugelf.as_deref(),
    )?;
    Ok(())
}
