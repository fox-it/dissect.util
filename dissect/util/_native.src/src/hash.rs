use pyo3::prelude::*;

mod crc32c;
mod crc64c;

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "hash")?;
    crc32c::create_submodule(&submodule)?;
    crc64c::create_submodule(&submodule)?;
    m.add_submodule(&submodule)
}
