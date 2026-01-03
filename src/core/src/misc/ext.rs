use log::warn;
use std::fmt::Debug;

pub trait ResultExt<T> {
    fn ok_or_warn(self) -> Option<T>;
}

impl<T, E: Debug> ResultExt<T> for Result<T, E> {
    fn ok_or_warn(self) -> Option<T> {
        self.inspect_err(|err| warn!("{err:?}")).ok()
    }
}
