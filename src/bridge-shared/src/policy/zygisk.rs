use wincode::{SchemaRead, SchemaWrite};

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
pub struct ZygiskParams {
    pub module_name: String,
}
