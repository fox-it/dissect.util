use std::borrow::Cow;

use pyo3::prelude::*;
use pyo3::types::PyTuple;

/// Inputs at least this large are hashed without holding the GIL / thread state.
const DETACH_THRESHOLD: usize = 64 * 1024;

macro_rules! crc_impl {
    ($name:ident, $ty:ty) => {
        /// A table-driven CRC with arbitrary parameters.
        ///
        /// Parameters follow the CRC catalogue (https://reveng.sourceforge.io/crc-catalogue/), where
        /// ``refin`` and ``refout`` are combined into ``reflected``.
        ///
        /// Args:
        ///     poly: The polynomial in normal (MSB-first) notation.
        ///     init: The initial value of the register.
        ///     xorout: The value to XOR the final register with.
        ///     reflected: Whether the CRC is reflected (LSB-first).
        ///
        #[pyclass(frozen, module = "dissect.util._native.hash.crc")]
        pub struct $name {
            table: [$ty; 256],
            #[pyo3(get)]
            poly: $ty,
            #[pyo3(get)]
            init: $ty,
            #[pyo3(get)]
            xorout: $ty,
            #[pyo3(get)]
            reflected: bool,
        }

        impl $name {
            const WIDTH: u32 = <$ty>::BITS;

            /// Build the lookup table at compile time (when called in a const context) or at runtime.
            pub const fn make_table(poly: $ty, reflected: bool) -> [$ty; 256] {
                let mut table = [0 as $ty; 256];
                let rpoly = poly.reverse_bits();
                let top: $ty = 1 << (Self::WIDTH - 1);

                let mut i = 0;
                while i < 256 {
                    let mut crc: $ty = if reflected {
                        i as $ty
                    } else {
                        (i as $ty) << (Self::WIDTH - 8)
                    };

                    let mut j = 0;
                    while j < 8 {
                        crc = if reflected {
                            if crc & 1 != 0 {
                                (crc >> 1) ^ rpoly
                            } else {
                                crc >> 1
                            }
                        } else if crc & top != 0 {
                            (crc << 1) ^ poly
                        } else {
                            crc << 1
                        };
                        j += 1;
                    }

                    table[i] = crc;
                    i += 1;
                }

                table
            }

            pub const fn new(poly: $ty, init: $ty, xorout: $ty, reflected: bool) -> Self {
                Self {
                    table: Self::make_table(poly, reflected),
                    poly,
                    init,
                    xorout,
                    reflected,
                }
            }

            /// Run the raw register over ``data``, without any init/xorout handling.
            #[inline]
            fn update_raw(&self, mut crc: $ty, data: &[u8]) -> $ty {
                if self.reflected {
                    for &b in data {
                        crc = self.table[((crc ^ b as $ty) & 0xFF) as usize] ^ (crc >> 8);
                    }
                } else {
                    for &b in data {
                        crc = self.table[(((crc >> (Self::WIDTH - 8)) ^ b as $ty) & 0xFF) as usize]
                            ^ (crc << 8);
                    }
                }
                crc
            }

            fn run(&self, py: Python<'_>, crc: $ty, data: &[u8]) -> $ty {
                if data.len() >= DETACH_THRESHOLD {
                    py.detach(|| self.update_raw(crc, data))
                } else {
                    self.update_raw(crc, data)
                }
            }

            /// Continue from a previously computed checksum (Rust-side API).
            pub fn checksum_from(&self, py: Python<'_>, value: $ty, data: &[u8]) -> $ty {
                self.run(py, value ^ self.xorout, data) ^ self.xorout
            }
        }

        #[pymethods]
        impl $name {
            #[new]
            #[pyo3(signature = (poly, init=0, xorout=0, reflected=true))]
            fn py_new(poly: $ty, init: $ty, xorout: $ty, reflected: bool) -> Self {
                Self::new(poly, init, xorout, reflected)
            }

            /// Update a checksum with data.
            ///
            /// Args:
            ///     crc: A previously computed checksum to continue from.
            ///     data: The data to update the checksum with.
            ///
            #[pyo3(signature = (crc, data))]
            fn update(&self, py: Python<'_>, crc: $ty, data: Cow<'_, [u8]>) -> $ty {
                self.checksum_from(py, crc, &data)
            }

            /// Calculate the checksum of some data, optionally continuing from a previous checksum.
            ///
            /// Args:
            ///     data: The data to calculate the checksum of.
            ///     value: A previously computed checksum to continue from. Default is to start a new checksum.
            ///
            #[pyo3(signature = (data, value=None))]
            fn __call__(&self, py: Python<'_>, data: Cow<'_, [u8]>, value: Option<$ty>) -> $ty {
                match value {
                    Some(value) => self.checksum_from(py, value, &data),
                    None => self.run(py, self.init, &data) ^ self.xorout,
                }
            }

            #[getter]
            fn table<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyTuple>> {
                PyTuple::new(py, self.table)
            }

            fn __repr__(&self) -> String {
                let digits = (Self::WIDTH / 4) as usize + 2;
                format!(
                    "<{} poly={:#0w$x} init={:#0w$x} xorout={:#0w$x} reflected={}>",
                    stringify!($name),
                    self.poly,
                    self.init,
                    self.xorout,
                    if self.reflected { "True" } else { "False" },
                    w = digits,
                )
            }
        }
    };
}

crc_impl!(Crc32, u32);
crc_impl!(Crc64, u64);

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "crc")?;
    submodule.add_class::<Crc32>()?;
    submodule.add_class::<Crc64>()?;
    m.add_submodule(&submodule)
}
