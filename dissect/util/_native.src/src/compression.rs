use pyo3::prelude::*;

mod lz4;
mod lzo;

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new_bound(m.py(), "compression")?;
    lz4::create_submodule(&submodule)?;
    lzo::create_submodule(&submodule)?;
    m.add_submodule(&submodule)
}
