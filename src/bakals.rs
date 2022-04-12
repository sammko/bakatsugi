use anyhow::Result;
use bakatsugi::inspection::get_symbols_own;
use clap::Parser;
use nix::{libc::pid_t, unistd::Pid};

#[derive(Debug, Parser)]
#[clap(version)]
struct Args {
    #[clap(short, long)]
    pid: pid_t,
}

fn main() -> Result<()> {
    let args = Args::parse();

    for s in get_symbols_own(Pid::from_raw(args.pid), false)? {
        println!("{}", s.get_name());
    }
    Ok(())
}
