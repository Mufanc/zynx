#[macro_export]
macro_rules! dynasm {
         ($ops:ident $($body:tt)*) => {
         {
             #[allow(unused_imports)]
             use dynasmrt::{DynasmApi, DynasmLabelApi};

             dynasmrt::dynasm!($ops
                 ; .arch aarch64
                 ; .alias ip, x17
                 ; .alias fp, x29
                 ; .alias lr, x30
                 $($body)*
             )
         }
     }
}
