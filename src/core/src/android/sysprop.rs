use std::ffi::{CStr, CString, c_char};

unsafe extern "C" {
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> u32;
}

// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/parsebool.cpp;l=23-31;drc=61197364367c9e404c7da6900658f1b16c42d0da
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "yes" | "on" | "true" => Some(true),
        "0" | "n" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}

pub fn get(name: &str) -> String {
    let name = CString::new(name).unwrap();
    let mut buffer = [0u8; 128];

    let prop = unsafe {
        __system_property_get(name.as_ptr(), buffer.as_mut_ptr() as _);
        CStr::from_bytes_until_nul(&buffer).unwrap()
    };

    prop.to_string_lossy().into()
}

pub fn get_bool(name: &str, fallback: bool) -> bool {
    parse_bool(&get(name)).unwrap_or(fallback)
}
