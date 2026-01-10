use log::{debug, warn};
use nix::unistd::{Gid, Uid};
use std::ops::Deref;

pub struct EmbryoCheckArgsFast {
    pub uid: Uid,
    pub gid: Gid,
    pub is_system_server: bool,
    pub is_child_zygote: bool,
}

pub struct EmbryoCheckArgsSlow {
    fast_args: EmbryoCheckArgsFast,
    pub nice_name: Option<String>,
    pub app_data_dir: Option<String>,
}

impl Deref for EmbryoCheckArgsSlow {
    type Target = EmbryoCheckArgsFast;

    fn deref(&self) -> &Self::Target {
        &self.fast_args
    }
}

pub enum EmbryoCheckArgs {
    Fast(EmbryoCheckArgsFast),
    Slow(EmbryoCheckArgsSlow),
}

impl EmbryoCheckArgs {
    pub fn new_fast(uid: Uid, gid: Gid, is_system_server: bool, is_child_zygote: bool) -> Self {
        EmbryoCheckArgs::Fast(EmbryoCheckArgsFast {
            uid,
            gid,
            is_system_server,
            is_child_zygote,
        })
    }

    pub fn into_slow(self, nice_name: Option<String>, app_data_dir: Option<String>) -> Self {
        EmbryoCheckArgs::Slow(EmbryoCheckArgsSlow {
            fast_args: match self {
                EmbryoCheckArgs::Fast(args) => args,
                EmbryoCheckArgs::Slow(args) => {
                    warn!("into_slow called on already slow args, ignoring conversion");
                    return Self::Slow(args);
                }
            },
            nice_name,
            app_data_dir,
        })
    }

    pub fn is_fast(&self) -> bool {
        matches!(self, EmbryoCheckArgs::Fast(_))
    }

    pub fn is_slow(&self) -> bool {
        !self.is_fast()
    }
}

pub enum EmbryoCheckResult {
    Deny,
    Allow,
    MoreInfo,
}

pub struct InjectorPolicy {}

impl InjectorPolicy {
    pub fn check_embryo(args: &EmbryoCheckArgs) -> EmbryoCheckResult {
        match args {
            EmbryoCheckArgs::Fast(_) => EmbryoCheckResult::MoreInfo,
            EmbryoCheckArgs::Slow(slow) => {
                debug!("nice name = {:?}", slow.nice_name);

                if slow.is_system_server {
                    EmbryoCheckResult::Allow
                } else {
                    EmbryoCheckResult::Deny
                }
            }
        }
    }
}
