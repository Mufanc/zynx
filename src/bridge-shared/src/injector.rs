use crate::remote_lib::Libraries;
use crate::zygote::{ProviderType, SpecializeArgs};
use anyhow::Result;

pub trait ProviderHandler: Send + Sync + 'static {
    const TYPE: ProviderType;

    fn on_specialize_pre(
        _args: &mut SpecializeArgs,
        _libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        Ok(())
    }

    fn on_specialize_post(
        _args: &SpecializeArgs,
        _libs: &mut Libraries,
        _data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        Ok(())
    }
}
