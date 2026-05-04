use wincode::{SchemaRead, SchemaWrite};

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
pub struct LiteLoaderParams {
    pub lib_name: String,
    pub kind: LibraryKind,
}

#[derive(Debug, Clone, SchemaRead, SchemaWrite)]
pub enum LibraryKind {
    Native,
    Java,
}
