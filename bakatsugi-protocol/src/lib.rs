use std::path::PathBuf;

use bincode::{
    config, decode_from_std_read, encode_into_std_write,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

#[derive(PartialEq, Eq, Encode, Decode, Debug)]
pub enum TrampolineKind {
    Indirect5,
    Absolute12,
}

#[derive(PartialEq, Eq, Encode, Decode, Debug)]
pub enum MessageItoT {
    Ping(u64),
    OpenDSO(i32, PathBuf),
    RecvDSO(i32, bool),
    PatchLib(String, i32, String),
    PatchOwn(String, i32, String, TrampolineKind),
    RecvDebugElf,
    Quit,
}

#[derive(PartialEq, Eq, Encode, Decode, Debug)]
pub enum MessageTtoI {
    Pong(u64),
    Ok,
}

pub trait Net {
    fn send<W: std::io::Write>(&self, write: &mut W) -> Result<usize, EncodeError>;
    fn recv<R: std::io::Read>(read: &mut R) -> Result<Self, DecodeError>
    where
        Self: Sized;
}

macro_rules! impl_net {
    ($t:ident) => {
        impl Net for $t {
            fn send<W: std::io::Write>(&self, write: &mut W) -> Result<usize, EncodeError> {
                let config = config::standard();
                encode_into_std_write(self, write, config)
            }

            fn recv<R: std::io::Read>(read: &mut R) -> Result<Self, DecodeError> {
                let config = config::standard();
                decode_from_std_read(read, config)
            }
        }
    };
}

impl_net!(MessageItoT);
impl_net!(MessageTtoI);
