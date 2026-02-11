use crate::dlfcn::Libraries;
use crate::zygote::{ProviderType, SpecializeArgs};
use anyhow::Result;

pub trait ProviderHandler: Send + Sync + 'static {
    const TYPE: ProviderType;

    fn on_specialize_pre(
        args: &mut SpecializeArgs,
        libs: Libraries,
        data: Option<Vec<u8>>,
    ) -> Result<()>;

    fn on_specialize_post(args: &SpecializeArgs) -> Result<()>;
}
