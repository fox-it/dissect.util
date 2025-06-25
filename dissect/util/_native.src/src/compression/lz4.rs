use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes};

const MAX_DISCOVER_OUTPUT_SIZE: usize = 1024 * 1024 * 1024;

fn decompress_to_unknown_size(src: &[u8]) -> Result<Vec<u8>, PyErr> {
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
                break Ok(result);
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
}

/// LZ4 decompress bytes up to a certain length. Assumes no header.
///
/// Unlike the Python implementation, this function does not support streaming decompression
/// (i.e. reading from a file-like object).
///
/// Args:
///     src: Bytes to decompress.
///     uncompressed_size: The uncompressed data size. If not provided or ``-1``, will try to discover it.
///     return_bytearray: Whether to return ``bytearray`` or ``bytes``.
///
/// Returns:
///     The decompressed data.
///
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
        decompress_to_unknown_size(&src)?
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
