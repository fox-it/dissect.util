use pyo3::prelude::*;

mod compression;

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    compression::create_submodule(m)?;
    Ok(())
}
