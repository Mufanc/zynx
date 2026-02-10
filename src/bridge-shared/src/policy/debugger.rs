use wincode::{SchemaRead, SchemaWrite};

#[derive(SchemaRead, SchemaWrite)]
pub struct DebuggerParams {
    pub force_debuggable: bool,
}
