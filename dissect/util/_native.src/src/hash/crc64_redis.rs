use std::borrow::Cow;

use pyo3::prelude::*;

use super::crc::Crc64;

/// CRC-64/REDIS: the Jones polynomial, reflected, init 0, xorout 0. The table is built at compile time.
static CRC: Crc64 = Crc64::new(0xAD93D23594C935A9, 0, 0, true);

/// Update CRC-64/REDIS checksum with data.
///
/// Args:
///     crc: The initial value of the checksum.
///     data: The data to update the checksum with.
///
/// Returns:
///     The computed CRC-64/REDIS.
///
#[pyfunction]
#[pyo3(signature = (crc, data))]
fn update(py: Python<'_>, crc: u64, data: Cow<'_, [u8]>) -> u64 {
    CRC.checksum_from(py, crc, &data)
}

/// Calculate CRC-64/REDIS checksum of some data, with an optional initial value.
///
/// Args:
///     data: The data to calculate the checksum of.
///     value: The initial value of the checksum. Default is 0.
///
/// Returns:
///     The computed CRC-64/REDIS.
///
#[pyfunction]
#[pyo3(signature = (data, value=0))]
fn crc64_redis(py: Python<'_>, data: Cow<'_, [u8]>, value: u64) -> u64 {
    CRC.checksum_from(py, value, &data)
}

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "crc64_redis")?;
    submodule.add_function(wrap_pyfunction!(update, m)?)?;
    submodule.add_function(wrap_pyfunction!(crc64_redis, m)?)?;
    m.add_submodule(&submodule)
}
