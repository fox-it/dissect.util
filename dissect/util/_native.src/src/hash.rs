use pyo3::prelude::*;

mod crc;
mod crc32c;
mod crc64_redis;
mod crc64c;

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "hash")?;
    crc::create_submodule(&submodule)?;
    crc32c::create_submodule(&submodule)?;
    crc64_redis::create_submodule(&submodule)?;
    crc64c::create_submodule(&submodule)?;
    m.add_submodule(&submodule)
}
