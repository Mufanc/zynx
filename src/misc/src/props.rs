use nix::libc::{self, PROP_VALUE_MAX};
use std::ffi::{CStr, CString};
use std::ops::Deref;

// https://cs.android.com/android/platform/superproject/main/+/main:system/libbase/parsebool.cpp;l=23-31;drc=61197364367c9e404c7da6900658f1b16c42d0da
fn parse_bool(value: &str) -> Option<bool> {
    match value {
        "1" | "y" | "yes" | "on" | "true" => Some(true),
        "0" | "n" | "no" | "off" | "false" => Some(false),
        _ => None,
    }
}

pub struct Property(String);

impl From<Property> for bool {
    fn from(value: Property) -> Self {
        parse_bool(&value).unwrap_or_default()
    }
}

impl Property {
    pub fn as_bool(&self) -> Option<bool> {
        parse_bool(self)
    }
}

impl Deref for Property {
    type Target = str;

    fn deref(&self) -> &str {
        &self.0
    }
}

pub fn get(name: &str) -> Option<Property> {
    let name = CString::new(name).ok()?;
    let mut buffer = [0u8; PROP_VALUE_MAX as usize];

    let len = unsafe { libc::__system_property_get(name.as_ptr(), buffer.as_mut_ptr() as _) };

    if len == 0 {
        return None;
    }

    let value = CStr::from_bytes_until_nul(&buffer).ok()?;
    Some(Property(value.to_string_lossy().into_owned()))
}

pub fn prop_on(name: &str) -> bool {
    get(name).map(|it| it.into()).unwrap_or_default()
}
