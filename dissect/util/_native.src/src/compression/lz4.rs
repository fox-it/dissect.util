use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};

const MAX_DISCOVER_OUTPUT_SIZE: usize = 1024 * 1024 * 1024;

#[pyfunction]
#[pyo3(signature = (src, uncompressed_size=-1, return_bytearray=false))]
fn decompress(
    py: Python<'_>,
    src: Vec<u8>,
    uncompressed_size: isize,
    return_bytearray: bool,
) -> PyResult<PyObject> {
    let result = if uncompressed_size < 0 {
        // If the uncompressed size is not provided, we need to discover it first
        let mut output_size = lz4_flex::block::get_maximum_output_size(src.len());
        loop {
            // If the output size is too large, we should not attempt to decompress further
            if output_size > MAX_DISCOVER_OUTPUT_SIZE {
                return Err(PyErr::new::<PyValueError, _>(
                    "output size is too large".to_string(),
                ));
            }

            match lz4_flex::block::decompress(&src, output_size) {
                Ok(result) => {
                    break result;
                }
                Err(lz4_flex::block::DecompressError::OutputTooSmall {
                    expected,
                    actual: _,
                }) => {
                    output_size = expected;
                }
                Err(e) => {
                    return Err(PyErr::new::<PyValueError, _>(e.to_string()));
                }
            }
        }
    } else {
        lz4_flex::block::decompress(&src, uncompressed_size as usize)
            .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))?
    };

    let pyresult = PyBytes::new(py, &result);
    if return_bytearray {
        Ok(PyByteArray::from(&pyresult)?.into())
    } else {
        Ok(pyresult.into())
    }
}

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new(m.py(), "lz4")?;
    submodule.add_function(wrap_pyfunction!(decompress, m)?)?;
    m.add_submodule(&submodule)
}
