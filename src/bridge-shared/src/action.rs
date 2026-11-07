use wincode::{SchemaRead, SchemaWrite};

#[derive(Debug, SchemaRead, SchemaWrite)]
pub enum ActionData {
    EnableDebugger,
    LoadNative { name: String },
    LoadJava { name: String },
    LoadZygisk { name: String },
}
