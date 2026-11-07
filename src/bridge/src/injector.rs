use anyhow::{Context, Result, ensure};
use log::error;
use std::os::fd::OwnedFd;
use zynx_bridge_api::action::Action;
use zynx_bridge_shared::action::ActionData;
use zynx_bridge_shared::remote_lib::{JavaLibrary, NativeLibrary};
use zynx_bridge_shared::zygote::SpecializeArgs;
#[cfg(feature = "zygisk")]
use zynx_zygisk_compat::PinnedZygiskModule;

#[derive(Debug)]
enum PreparedAction {
    EnableDebugger,
    LoadNative {
        name: String,
        fd: OwnedFd,
    },
    LoadJava {
        name: String,
        fd: OwnedFd,
    },
    #[cfg(feature = "zygisk")]
    LoadZygisk {
        name: String,
        fd: OwnedFd,
    },
}

impl PreparedAction {
    fn parse(action: Action) -> Result<Self> {
        let data: ActionData = wincode::deserialize(&action.data)?;

        match data {
            ActionData::EnableDebugger => {
                ensure!(action.fd.is_none(), "debugger action must not have an FD");
                Ok(Self::EnableDebugger)
            }
            ActionData::LoadNative { name } => Ok(Self::LoadNative {
                name,
                fd: action.fd.context("native action is missing its FD")?,
            }),
            ActionData::LoadJava { name } => Ok(Self::LoadJava {
                name,
                fd: action.fd.context("Java action is missing its FD")?,
            }),
            #[cfg(feature = "zygisk")]
            ActionData::LoadZygisk { name } => Ok(Self::LoadZygisk {
                name,
                fd: action.fd.context("Zygisk action is missing its FD")?,
            }),
            #[cfg(not(feature = "zygisk"))]
            ActionData::LoadZygisk { .. } => {
                anyhow::bail!("Zygisk action requires a Zygisk bridge")
            }
        }
    }
}

pub struct ActionExecutor {
    actions: Vec<PreparedAction>,
    #[cfg(feature = "zygisk")]
    modules: Vec<PinnedZygiskModule>,
}

impl ActionExecutor {
    pub fn new(actions: Vec<Action>) -> Result<Self> {
        let actions = actions
            .into_iter()
            .map(PreparedAction::parse)
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            actions,
            #[cfg(feature = "zygisk")]
            modules: Vec::new(),
        })
    }

    pub fn specialize_pre(&mut self, args: &mut SpecializeArgs) {
        for action in std::mem::take(&mut self.actions) {
            match action {
                PreparedAction::EnableDebugger => enable_debugger(args),
                #[cfg(feature = "zygisk")]
                PreparedAction::LoadZygisk { name, fd } => {
                    match zynx_zygisk_compat::load(name.clone(), fd, args.env) {
                        Ok(Some(module)) => self.modules.push(module),
                        Ok(None) => {}
                        Err(error) => error!("failed to load Zygisk module {name}: {error:#}"),
                    }
                }
                action => self.actions.push(action),
            }
        }

        #[cfg(feature = "zygisk")]
        for module in &self.modules {
            module.call_specialize_pre(args);
        }
    }

    pub fn specialize_post(self, args: &SpecializeArgs) {
        #[cfg(feature = "zygisk")]
        {
            for module in &self.modules {
                module.call_specialize_post(args);
            }

            drop(self.modules);
        }

        for action in self.actions {
            let result = match action {
                PreparedAction::LoadNative { name, fd } => NativeLibrary::new(name, fd).dlopen(),
                PreparedAction::LoadJava { name, fd } => JavaLibrary::new(name, fd).load(args.env),
                _ => continue,
            };

            if let Err(error) = result {
                error!("failed to execute load action: {error:#}");
            }
        }
    }
}

fn enable_debugger(args: &mut SpecializeArgs) {
    args.runtime_flags |= 1 // DEBUG_ENABLE_JDWP
        | (1 << 25) // DEBUG_ENABLE_PTRACE
        | (1 << 8) // DEBUG_JAVA_DEBUGGABLE
        | (1 << 1); // DEBUG_ENABLE_CHECKJNI
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use zynx_bridge_shared::zygote::SpecializeVersion;

    fn action(fd: bool, data: ActionData) -> Action {
        Action {
            fd: fd.then(|| File::open("/dev/null").unwrap().into()),
            data: wincode::serialize(&data).unwrap(),
        }
    }

    #[test]
    fn validates_operations_and_fd_requirements_before_execution() {
        assert!(
            ActionExecutor::new(vec![action(
                false,
                ActionData::LoadNative {
                    name: "test".into()
                }
            )])
            .is_err()
        );
        assert!(
            ActionExecutor::new(vec![action(
                false,
                ActionData::LoadJava {
                    name: "test".into()
                }
            )])
            .is_err()
        );
        assert!(ActionExecutor::new(vec![action(true, ActionData::EnableDebugger)]).is_err());
        assert!(
            PreparedAction::parse(action(
                false,
                ActionData::LoadZygisk {
                    name: "test".into()
                }
            ))
            .is_err()
        );
        let zygisk = PreparedAction::parse(action(
            true,
            ActionData::LoadZygisk {
                name: "test".into(),
            },
        ));
        assert_eq!(zygisk.is_ok(), cfg!(feature = "zygisk"));
        assert!(
            ActionExecutor::new(vec![Action {
                fd: None,
                data: vec![]
            }])
            .is_err()
        );
        assert!(
            ActionExecutor::new(vec![action(
                true,
                ActionData::LoadNative {
                    name: "test".into()
                }
            )])
            .is_ok()
        );
    }

    #[test]
    fn enables_debugging_and_defers_library_loads_in_order() {
        let mut executor = ActionExecutor::new(vec![
            action(
                true,
                ActionData::LoadNative {
                    name: "native".into(),
                },
            ),
            action(false, ActionData::EnableDebugger),
            action(
                true,
                ActionData::LoadJava {
                    name: "java".into(),
                },
            ),
        ])
        .unwrap();
        let mut raw_args = vec![0; SpecializeVersion::V.args_count()];
        let mut args = SpecializeArgs::new(&mut raw_args, SpecializeVersion::V);
        args.runtime_flags = 1 << 16;
        executor.specialize_pre(&mut args);
        assert_eq!(
            args.runtime_flags,
            (1 << 16) | 1 | (1 << 25) | (1 << 8) | (1 << 1)
        );
        assert!(matches!(executor.actions.as_slice(), [
            PreparedAction::LoadNative { name: native, .. },
            PreparedAction::LoadJava { name: java, .. },
        ] if native == "native" && java == "java"));
    }
}
