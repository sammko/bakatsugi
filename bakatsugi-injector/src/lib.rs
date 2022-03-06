#![feature(let_else)]
#![feature(peer_credentials_unix_socket)]
#![feature(unix_socket_abstract)]
#![feature(unix_socket_ancillary_data)]

mod inspection;

use std::{
    ffi::{c_void, CStr},
    fs::{self, File},
    io::{IoSlice, Read, Seek, Write},
    mem,
    net::Shutdown,
    os::unix::{
        net::SocketAddr,
        net::{SocketAncillary, UnixListener, UnixStream},
        prelude::{AsRawFd, FromRawFd, RawFd},
    },
    path::Path,
    str,
};

use anyhow::{bail, Context, Result};
use bakatsugi_payload::generate_payload;
use bakatsugi_protocol::{MessageItoT, MessageTtoI, Net};
use goblin::elf::Elf;
use nix::{
    libc::{
        SYS_mmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE, PTRACE_EVENT_STOP,
    },
    sys::{
        memfd::{memfd_create, MemFdCreateFlag},
        ptrace::{self, AddressType},
        signal::Signal,
        uio::{process_vm_writev, IoVec, RemoteIoVec},
        wait::{self, WaitStatus},
    },
    unistd::{close, Pid},
};
use rand::{distributions::Alphanumeric, Rng};

use inspection::get_dlopen_vmaddr;

fn generate_random_cookie() -> [u8; 16] {
    let mut rng = rand::thread_rng();
    let mut cookie = [0u8; 16];
    for x in &mut cookie {
        *x = rng.sample(&Alphanumeric);
    }
    cookie
}

fn create_bakatsugi_memfd() -> Result<RawFd> {
    const STAGE2_ELF: &[u8] = include_bytes!(env!("CARGO_CDYLIB_FILE_BAKATSUGI_STAGE2"));
    let memfd = memfd_create(
        CStr::from_bytes_with_nul(b"libbakatsugi\0").unwrap(),
        MemFdCreateFlag::empty(),
    )
    .context("memfd_create failed")?;
    let mut file = unsafe { File::from_raw_fd(memfd) };
    file.write_all(STAGE2_ELF)
        .context("Failed to write stage2 lib to memfd")?;
    mem::forget(file);
    Ok(memfd)
}

fn bind_listener(cookie: &[u8; 16]) -> Result<UnixListener> {
    let addr = SocketAddr::from_abstract_namespace(cookie).unwrap();
    UnixListener::bind_addr(&addr).context("bind_addr failed")
}

fn accept_target_connection(listener: &UnixListener, pid: Pid) -> Result<UnixStream> {
    let mut got_pid = false;
    let socket = loop {
        let (socket, _) = listener.accept().context("accept failed")?;
        if let Ok(uc) = socket.peer_cred() {
            if let Some(rpid) = uc.pid {
                if Pid::from_raw(rpid) == pid {
                    break socket;
                }
                println!("Ignore conn from pid: {}", rpid);
                got_pid = true;
            }
        }
        if !got_pid {
            println!("Ignore conn from unknown pid");
        }
        match socket.shutdown(Shutdown::Both) {
            Ok(_) => {}
            Err(_) => {
                println!("Failed to shutdown ignored connection")
            }
        }
    };
    Ok(socket)
}

fn send_fd(fd: i32, sock: &UnixStream) -> Result<()> {
    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[fd]);
    sock.send_vectored_with_ancillary(&[IoSlice::new(&[0])], &mut ancillary)
        .context("send fd failed")?;
    Ok(())
}

#[derive(Debug)]
enum PatchSpec<'a> {
    Own { old: &'a str, new: &'a str },
    Lib { old: &'a str, new: &'a str },
}

fn parse_patchspec(patchlib: &[u8]) -> Result<Vec<PatchSpec>> {
    let elf = Elf::parse(patchlib)?;
    let mut r = Vec::new();
    let mut section = None;
    for shdr in &elf.section_headers {
        if elf.shdr_strtab.get_at(shdr.sh_name) == Some("bakatsugi") {
            section = Some(shdr);
        }
    }
    let Some(section) = section else { bail!("Could not find metadata section in patch lib") };
    let range = section
        .file_range()
        .context("Section has no range in file")?;
    let section_data = &patchlib[range];
    if section_data[section_data.len() - 1] != 0 {
        bail!("Not null terminated");
    }
    let section_data = &section_data[..section_data.len() - 1];
    for line in section_data.split(|&b| b == b'\n') {
        if line.is_empty() {
            continue;
        }
        r.push(match line[0] {
            flag @ (b'O' | b'L') => {
                if let [l, r] = &str::from_utf8(&line[1..])?
                    .split('.')
                    .collect::<Vec<&str>>()[..]
                {
                    match flag {
                        b'O' => PatchSpec::Own { old: l, new: r },
                        b'L' => PatchSpec::Lib { old: l, new: r },
                        _ => unreachable!(),
                    }
                } else {
                    bail!("Malformed line in patchspec")
                }
            }
            _ => bail!("Bad flag in patchspec: {:x}", line[0]),
        });
    }
    Ok(r)
}

fn handle_stage2(socket: &mut UnixStream, patchlib: &Path, debugelf: Option<&Path>) -> Result<()> {
    let mut patchfd = fs::File::open(patchlib).context("Could not open patchlib")?;
    let mut patchelf = Vec::new();
    patchfd
        .read_to_end(&mut patchelf)
        .context("Could not read patchlib")?;
    patchfd.rewind().context("Could not rewind patchlib")?;
    let patches = parse_patchspec(&patchelf).context("Could not parse patchspec")?;

    MessageItoT::Ping(33).send(socket)?;
    let MessageTtoI::Pong(33) = MessageTtoI::recv(socket)? else { bail!("BAD") };

    MessageItoT::RecvDSO(1).send(socket)?;
    send_fd(patchfd.as_raw_fd(), socket)?;
    drop(patchfd);

    let MessageTtoI::Ok = MessageTtoI::recv(socket)? else { bail!("BAD") };

    if let Some(debugpath) = debugelf {
        MessageItoT::RecvDebugElf.send(socket)?;
        let debugfd = fs::File::open(debugpath)?;
        send_fd(debugfd.as_raw_fd(), socket)?;
        drop(debugfd);

        let MessageTtoI::Ok = MessageTtoI::recv(socket)? else { bail!("BAD") };
    }

    for patch in patches {
        println!("Patch: {:?}", patch);
        match patch {
            PatchSpec::Own { old, new } => {
                MessageItoT::PatchOwn(old.to_string(), 1, new.to_string())
            }
            PatchSpec::Lib { old, new } => {
                MessageItoT::PatchLib(old.to_string(), 1, new.to_string())
            }
        }
        .send(socket)?;
        let MessageTtoI::Ok = MessageTtoI::recv(socket)? else { bail!("BAD") };
    }

    MessageItoT::Quit.send(socket)?;

    Ok(())
}

pub fn do_inject(pid: Pid, patchlib: &Path, debugelf: Option<&Path>) -> Result<()> {
    let bakatsugi_memfd = create_bakatsugi_memfd()?;

    ptrace::seize(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD).context("ptrace::seize failed")?;
    ptrace::interrupt(pid).context("ptrace::interrupt failed")?;

    let dlopen_vmaddr =
        get_dlopen_vmaddr(pid).context("Could not find address of dlopen in target")?;

    let waitstatus = wait::waitpid(pid, None).context("waitpid failed")?;
    if !matches!(
        waitstatus,
        WaitStatus::PtraceEvent(_pid, Signal::SIGTRAP, PTRACE_EVENT_STOP)
    ) {
        bail!(
            "Unexpected WaitStatus after ptrace::interrupt: {:?}",
            waitstatus
        );
    }

    let saved_regs = ptrace::getregs(pid).context("ptrace::getregs failed")?;
    let addr = saved_regs.rip as AddressType;
    let saved_instr = ptrace::read(pid, addr).context("ptrace::read failed")?;
    unsafe {
        ptrace::write(pid, addr, 0x050F as *mut c_void).context("ptrace::write failed")?;
    }

    let mut modified_regs = saved_regs;

    modified_regs.rax = SYS_mmap as u64; // sys_mmap
    modified_regs.rdi = 0; // addr
    modified_regs.rsi = 4096; // length
    modified_regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC) as u64; // prot = RWX
    modified_regs.r10 = (MAP_PRIVATE | MAP_ANONYMOUS) as u64; // flags = MAP_PRIVATE | MAP_ANONYMOUS
    modified_regs.r8 = 0; // fd
    modified_regs.r9 = 0; // off

    ptrace::setregs(pid, modified_regs).context("ptrace::setregs failed")?;
    ptrace::step(pid, None).context("ptrace::step failed")?;

    let waitstatus = wait::waitpid(pid, None).context("waitpid failed")?;
    if !matches!(waitstatus, WaitStatus::Stopped(_pid, Signal::SIGTRAP)) {
        bail!("Unexpected WaitStatus after ptrace::step: {:?}", waitstatus);
    }

    let mmap_res = ptrace::getregs(pid).context("ptrace::getregs failed")?.rax;
    println!("Got page at 0x{:x}", mmap_res);
    unsafe {
        ptrace::write(pid, addr, saved_instr as *mut c_void).context("ptrace::write failed")?;
    }

    let cookie = generate_random_cookie();
    let payload = generate_payload(mmap_res, dlopen_vmaddr, &cookie);

    println!("Writing {} bytes", payload.len());
    process_vm_writev(
        pid,
        &[IoVec::from_slice(&payload)],
        &[RemoteIoVec {
            base: mmap_res as usize,
            len: payload.len(),
        }],
    )?;

    let mut modified2_regs = saved_regs;

    // +2 to compensate kernel's syscall restart mechanism.
    // payload can be entered at both offset 0 and 2 to
    // work in non-sycall case as well
    // is there a better way?
    // does the syscall get skipped in a retarded manner, or
    // is it restarted later in the future (the next CONT after
    // this one, or detach)?
    //
    // https://github.com/DynamoRIO/dynamorio/pull/5019/files/d2407f3621d583fe0f39c0136fe5c902acb2ff0f#r688968077
    modified2_regs.rip = mmap_res + 2;

    // TODO: if we interrupt in a leaf function, we must not clobber the red zone.
    // is this correct? Alignment is necessary, otherwise movdqa breaks in libc
    // the +16 is to accomodate metadata passing
    modified2_regs.rsp = ((modified2_regs.rsp - 128 - 16) & 0xfffffffffffff000) + 16;
    println!("Stack is at 0x{:016x}", modified2_regs.rsp);
    ptrace::setregs(pid, modified2_regs).context("ptrace::setregs failed")?;

    let listener = bind_listener(&cookie)?;

    println!("Running payload");
    ptrace::cont(pid, None).context("ptrace::cont failed")?;

    let socket = accept_target_connection(&listener, pid)?;

    println!("Sending fd");
    send_fd(bakatsugi_memfd, &socket)?;
    close(bakatsugi_memfd).context("Failed to close memfd")?;
    socket.shutdown(Shutdown::Both).context("shutdown failed")?;

    println!("Waiting for stage2 connection");
    let mut socket = accept_target_connection(&listener, pid)?;
    drop(listener);

    match handle_stage2(&mut socket, patchlib, debugelf) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("stage2 failed: {}", e)
        }
    }

    let waitstatus = wait::waitpid(pid, None).context("waitpid failed")?;
    if !matches!(waitstatus, WaitStatus::Stopped(_pid, Signal::SIGTRAP)) {
        bail!("Unexpected WaitStatus after ptrace::cont: {:?}", waitstatus);
    }

    println!("Restoring and detaching");
    ptrace::setregs(pid, saved_regs).context("ptrace::setregs failed")?;
    ptrace::detach(pid, None).context("ptrace::detach failed")?;

    Ok(())
}
