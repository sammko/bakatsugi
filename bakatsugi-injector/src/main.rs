#![feature(let_else)]
#![feature(peer_credentials_unix_socket)]
#![feature(unix_socket_abstract)]
#![feature(unix_socket_ancillary_data)]

use std::{
    ffi::{c_void, CStr, OsString},
    fs::{self, File},
    io::{IoSlice, Read, Write},
    mem,
    net::Shutdown,
    os::unix::{
        net::SocketAddr,
        net::{SocketAncillary, UnixListener, UnixStream},
        prelude::{FromRawFd, RawFd},
    },
    path::PathBuf,
};

use anyhow::{bail, Context, Result};
use bakatsugi_payload::generate_payload;
use goblin::Object;
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
use proc_maps::MapRange;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;

fn get_libc_text_maprange(pid: Pid) -> Result<MapRange> {
    let re = Regex::new(r"^libc(-[0-9.]+)?\.so[0-9.]*$")?;
    for map in proc_maps::get_process_maps(pid.as_raw())? {
        // ASSUMPTION: libc contains only one executable mapping,
        // corresponding to the LOAD phdr containing .text.
        if !map.is_exec() {
            continue;
        }
        if let Some(basename) = map.filename().and_then(|f| f.file_name()) {
            match basename.to_str() {
                Some(s) => {
                    if re.is_match(s) {
                        return Ok(map);
                    }
                }
                None => continue,
            }
        }
    }
    bail!("Could not find libc in target")
}

fn get_mapfile(pid: Pid, maprange: &MapRange) -> PathBuf {
    PathBuf::from(format!(
        "/proc/{}/map_files/{:x}-{:x}",
        pid.as_raw(),
        maprange.start(),
        maprange.start() + maprange.size()
    ))
}

fn get_dlopen_vmaddr(pid: Pid) -> Result<u64> {
    let map = get_libc_text_maprange(pid)?;
    let libc = fs::read(get_mapfile(pid, &map))?;
    let Object::Elf(elf) = Object::parse(&libc)? else { bail!("libc file not ELF") };

    let dynstrtab = elf.dynstrtab;
    for sym in elf.dynsyms.iter() {
        let name = dynstrtab.get_at(sym.st_name);
        // glibc 2.34 removes __libc_dlopen_mode but instead
        // libdl is merged in, including normal dlopen. Same signature,
        // don't care which one it is.
        if let Some("__libc_dlopen_mode" | "dlopen") = name {
            return Ok(sym.st_value - map.offset as u64 + map.start() as u64);
        }
    }
    bail!("Could not find dlopen");
}

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
    )?;
    let mut file = unsafe { File::from_raw_fd(memfd) };
    file.write_all(STAGE2_ELF)?;
    mem::forget(file);
    Ok(memfd)
}

fn bind_listener(cookie: &[u8; 16]) -> Result<UnixListener> {
    let addr = SocketAddr::from_abstract_namespace(cookie)?;
    Ok(UnixListener::bind_addr(&addr)?)
}

fn accept_target_connection(listener: &UnixListener, pid: Pid) -> Result<UnixStream> {
    let mut got_pid = false;
    let socket = loop {
        let (socket, _) = listener.accept()?;
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
        socket.shutdown(Shutdown::Both)?;
    };
    Ok(socket)
}

fn main() -> Result<()> {
    let args: Vec<OsString> = std::env::args_os().collect();
    let pid = Pid::from_raw(args[1].to_str().context("pid not utf8")?.parse::<i32>()?);
    let bakatsugi_memfd = create_bakatsugi_memfd()?;

    ptrace::seize(pid, ptrace::Options::PTRACE_O_TRACESYSGOOD)?;
    ptrace::interrupt(pid)?;

    let dlopen_vmaddr = get_dlopen_vmaddr(pid)?;

    let waitstatus = wait::waitpid(pid, None)?;
    if !matches!(
        waitstatus,
        WaitStatus::PtraceEvent(_pid, Signal::SIGTRAP, PTRACE_EVENT_STOP)
    ) {
        bail!(
            "Unexpected WaitStatus after ptrace::interrupt: {:?}",
            waitstatus
        );
    }

    let saved_regs = ptrace::getregs(pid).context("getregs")?;
    let addr = saved_regs.rip as AddressType;
    let saved_instr = ptrace::read(pid, addr).context("read")?;
    unsafe {
        ptrace::write(pid, addr, 0x050F as *mut c_void).context("write")?;
    }

    let mut modified_regs = saved_regs;

    modified_regs.rax = SYS_mmap as u64; // sys_mmap
    modified_regs.rdi = 0; // addr
    modified_regs.rsi = 4096; // length
    modified_regs.rdx = (PROT_READ | PROT_WRITE | PROT_EXEC) as u64; // prot = RWX
    modified_regs.r10 = (MAP_PRIVATE | MAP_ANONYMOUS) as u64; // flags = MAP_PRIVATE | MAP_ANONYMOUS
    modified_regs.r8 = 0; // fd
    modified_regs.r9 = 0; // off

    ptrace::setregs(pid, modified_regs).context("setregs")?;
    ptrace::step(pid, None).context("step")?;

    let waitstatus = wait::waitpid(pid, None)?;
    if !matches!(waitstatus, WaitStatus::Stopped(_pid, Signal::SIGTRAP)) {
        bail!("Unexpected WaitStatus after ptrace::step: {:?}", waitstatus);
    }

    let mmap_res = ptrace::getregs(pid).context("getregs2")?.rax;
    println!("Got page at 0x{:x}", mmap_res);
    unsafe {
        ptrace::write(pid, addr, saved_instr as *mut c_void).context("write2")?;
    }

    let cookie = generate_random_cookie();
    let payload =
        generate_payload(mmap_res, dlopen_vmaddr, &cookie).context("Failed to generate payload")?;

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
    ptrace::setregs(pid, modified2_regs).context("setregs2")?;

    let listener = bind_listener(&cookie)?;

    println!("Running payload");
    ptrace::cont(pid, None)?;

    let socket = accept_target_connection(&listener, pid)?;

    println!("Sending fd");

    let mut ancillary_buffer = [0; 128];
    let mut ancillary = SocketAncillary::new(&mut ancillary_buffer);
    ancillary.add_fds(&[bakatsugi_memfd]);
    socket.send_vectored_with_ancillary(&[IoSlice::new(&[0])], &mut ancillary)?;

    close(bakatsugi_memfd)?;

    socket.shutdown(Shutdown::Both)?;

    let waitstatus = wait::waitpid(pid, None)?;
    if !matches!(waitstatus, WaitStatus::Stopped(_pid, Signal::SIGTRAP)) {
        bail!("Unexpected WaitStatus after ptrace::cont: {:?}", waitstatus);
    }

    println!("Restoring and detaching");
    ptrace::setregs(pid, saved_regs)?;
    ptrace::detach(pid, None).context("detach")?;

    let mut socket = accept_target_connection(&listener, pid)?;
    drop(listener);
    let mut s = String::new();
    socket.read_to_string(&mut s)?;
    println!("recvd from stage2: {}", &s);

    Ok(())
}