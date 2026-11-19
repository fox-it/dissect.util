use pyo3::prelude::*;
use pyo3::pybacked::PyBackedBytes;

/// A bytes-like argument. A ``bytes`` is borrowed and a ``bytearray`` copied in one go. Extracting
/// either as a ``Vec<u8>`` goes through it as a sequence, an int at a time, which costs ~10 ns a
/// byte: most of the time of a call. Other sequences of ints are still accepted that way.
#[derive(FromPyObject)]
pub enum Buffer {
    Bytes(PyBackedBytes),
    Sequence(Vec<u8>),
}

impl std::ops::Deref for Buffer {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            Buffer::Bytes(bytes) => bytes,
            Buffer::Sequence(sequence) => sequence,
        }
    }
}
