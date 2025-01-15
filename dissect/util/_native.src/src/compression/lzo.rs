use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::PyBytes;

#[pyfunction]
#[pyo3(signature = (src, header=true, buflen=-1))]
fn decompress(
    py: Python<'_>,
    src: Vec<u8>,
    header: bool,
    buflen: isize,
) -> PyResult<Bound<'_, PyBytes>> {
    let (src, out_len) = if header {
        if src.len() < 8 || src[0] < 0xf0 || src[0] > 0xf1 {
            return Err(PyErr::new::<PyValueError, _>(
                "Invalid header value".to_string(),
            ));
        }
        let len = u32::from_le_bytes([src[1], src[2], src[3], src[4]]) as usize;
        (src[5..].to_vec(), len)
    } else if buflen < 0 {
        return Err(PyErr::new::<PyValueError, _>(
            "Buffer length must be provided".to_string(),
        ));
    } else {
        (src, buflen as usize)
    };

    let mut cursor = std::io::Cursor::new(src);
    lzokay_native::decompress(&mut cursor, Some(out_len))
        .map_err(|e| PyErr::new::<PyValueError, _>(e.to_string()))
        .map(|result| PyBytes::new_bound(py, &result))
}

pub fn create_submodule(m: &Bound<'_, PyModule>) -> PyResult<()> {
    let submodule = PyModule::new_bound(m.py(), "lzo")?;
    submodule.add_function(wrap_pyfunction!(decompress, m)?)?;
    m.add_submodule(&submodule)
}
