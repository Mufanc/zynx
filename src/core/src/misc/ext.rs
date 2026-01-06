use log::{error, warn};
use std::fmt::Debug;

pub trait ResultExt<T> {
    fn ok_or_warn(self) -> Option<T>;
    fn log_if_error(self);
}

impl<T, E: Debug> ResultExt<T> for Result<T, E> {
    fn ok_or_warn(self) -> Option<T> {
        self.inspect_err(|err| warn!("warn: {err:?}")).ok()
    }

    fn log_if_error(self) {
        if let Err(err) = self {
            error!("error: {err:?}")
        }
    }
}
