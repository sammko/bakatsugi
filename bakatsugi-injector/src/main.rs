use std::ffi::OsString;

use anyhow::{Context, Result};
use bakatsugi_injector::do_inject;
use nix::unistd::Pid;

fn main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let pid = Pid::from_raw(args[1].to_str().context("pid not utf8")?.parse::<i32>()?);

    do_inject(pid)?;
    Ok(())
}
