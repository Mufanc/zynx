#[macro_export]
macro_rules! debug_on {
    ($key: expr) => {{
        #[cfg(debug_assertions)]
        {
            $crate::props::prop_on(concat!("debug.zynx.", $key))
        }
        #[cfg(not(debug_assertions))]
        {
            false
        }
    }};
}
