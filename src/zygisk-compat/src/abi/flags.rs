#[repr(i32)]
#[derive(Copy, Clone)]
pub enum ZygiskOption {
    ForceDenylistUnmount = 0,
    DlcloseModuleLibrary = 1,
}

impl ZygiskOption {
    pub const MAX_INDEX: usize = Self::DlcloseModuleLibrary as usize;

    pub fn index(&self) -> usize {
        *self as _
    }
}

#[repr(u32)]
#[derive(Copy, Clone)]
pub enum ZygiskStateFlag {
    ProcessGrantedRoot = 1 << 0,
    _ProcessOnDenylist = 1 << 1, // unsupported, processes on the `denylist` will not be injected
}
