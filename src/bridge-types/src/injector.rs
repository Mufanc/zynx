use crate::dlfcn::Library;
use crate::zygote::{ProviderType, SpecializeArgs};
use anyhow::Result;

pub trait ProviderHandler: Send + Sync + 'static {
    const TYPE: ProviderType;

    fn on_specialize_pre(args: &mut SpecializeArgs, libs: Vec<Library>) -> Result<()>;
    fn on_specialize_post(args: &SpecializeArgs) -> Result<()>;
}
