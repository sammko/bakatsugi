use bincode::{
    config, decode_from_std_read, encode_into_std_write,
    error::{DecodeError, EncodeError},
    Decode, Encode,
};

#[derive(Encode, Decode, Debug)]
pub enum MessageItoT {
    Ping(u64),
    Quit,
}

#[derive(Encode, Decode, Debug)]
pub enum MessageTtoI {
    Pong(u64),
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
