use core::slice;
use std::ffi::c_void;

use nix::libc;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TrampolineError {
    #[error("Could not mmap page")]
    Mmap,
    #[error("Not enough space")]
    NotEnoughSpace,
    #[error("Too far away from rip")]
    TooFarAway,
}

pub struct TrampolineAllocator {
    data: &'static mut [u8],
    current_offset: usize,
}

const PAGE_SIZE: usize = 4096;

pub fn make_large_trampoline(target: u64) -> Vec<u8> {
    let mut trampoline = b"\x48\xb8\x00\x00\x00\x00\x00\x00\x00\x10\xff\xe0".to_vec();
    trampoline[2..10].copy_from_slice(&target.to_le_bytes());
    trampoline
}

impl TrampolineAllocator {
    pub fn new(base: usize) -> Result<Self, TrampolineError> {
        eprintln!("trampoline allocator base: 0x{:x}", base);
        let data = unsafe {
            let ptr = libc::mmap(
                base as *mut c_void,
                PAGE_SIZE,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
                libc::MAP_ANONYMOUS | libc::MAP_PRIVATE,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(TrampolineError::Mmap);
            }
            eprintln!("trampoline allocator mmap: 0x{:x}", ptr as usize);
            slice::from_raw_parts_mut(ptr as *mut u8, PAGE_SIZE)
        };
        Ok(Self {
            data,
            current_offset: 0,
        })
    }

    fn make_small(target_rel: i32) -> Vec<u8> {
        let mut trampoline = b"\xe9\x00\x00\x00\x00".to_vec();
        trampoline[1..5].copy_from_slice(&target_rel.to_le_bytes());
        trampoline
    }

    pub fn write_next_trampoline(
        &mut self,
        rip: u64,
        target: u64,
    ) -> Result<Vec<u8>, TrampolineError> {
        let rip = rip + 5;
        let trampoline = make_large_trampoline(target);
        if self.current_offset + trampoline.len() > self.data.len() {
            return Err(TrampolineError::NotEnoughSpace);
        }

        eprintln!(
            "rip: 0x{:x}, addr: 0x{:x}",
            rip,
            self.data[self.current_offset..].as_ptr() as u64
        );
        let distance = self.data[self.current_offset..].as_ptr() as i128 - rip as i128;
        eprintln!("distance: {}", distance);
        let distance32 = i32::try_from(distance).map_err(|_| TrampolineError::TooFarAway)?;

        self.data[self.current_offset..self.current_offset + trampoline.len()]
            .copy_from_slice(&trampoline);
        self.current_offset += trampoline.len();

        let small_trampoline = TrampolineAllocator::make_small(distance32);
        Ok(small_trampoline)
    }
}
