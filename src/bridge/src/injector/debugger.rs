use anyhow::Result;
use zynx_bridge_shared::dlfcn::Libraries;
use zynx_bridge_shared::injector::ProviderHandler;
use zynx_bridge_shared::policy::debugger::DebuggerParams;
use zynx_bridge_shared::zygote::{ProviderType, SpecializeArgs};

pub struct DebuggerProviderHandler;

impl ProviderHandler for DebuggerProviderHandler {
    const TYPE: ProviderType = ProviderType::Debugger;

    fn on_specialize_pre(
        args: &mut SpecializeArgs,
        _libs: &mut Libraries,
        data: &mut Option<Vec<u8>>,
    ) -> Result<()> {
        if let Some(bytes) = data {
            let params: DebuggerParams = wincode::deserialize(bytes)?;

            if params.force_debuggable {
                // https://cs.android.com/android/platform/superproject/main/+/main:frameworks/base/services/core/java/com/android/server/am/ProcessList.java;l=1946;drc=61197364367c9e404c7da6900658f1b16c42d0da
                args.runtime_flags |= 1 // DEBUG_ENABLE_JDWP
                    | (1 << 25) // DEBUG_ENABLE_PTRACE
                    | (1 << 8) // DEBUG_JAVA_DEBUGGABLE
                    | (1 << 1); // DEBUG_ENABLE_CHECKJNI
            }
        }

        Ok(())
    }
}
