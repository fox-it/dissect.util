use pyo3::prelude::*;

mod compression;
mod hash;

#[pymodule(gil_used = false)]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    compression::create_submodule(m)?;
    hash::create_submodule(m)?;
    Ok(())
}
