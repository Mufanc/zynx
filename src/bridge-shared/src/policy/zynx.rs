use wincode::{SchemaRead, SchemaWrite};

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
pub struct ZynxParams {
    pub module_name: String,
}
