use pyo3::prelude::*;

mod crc32c;

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "hash")?;
    crc32c::create_submodule(&submodule)?;
    m.add_submodule(&submodule)
}
