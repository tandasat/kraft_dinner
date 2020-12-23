pub use ntapi::ntdbg::DbgPrintEx;
pub const DPFLTR_IHVDRIVER_ID: u32 = 77;
pub const DPFLTR_ERROR_LEVEL: u32 = 0;

#[macro_export]
macro_rules! log {
    ($string: expr) => {
        unsafe {
            $crate::log::DbgPrintEx(
                crate::log::DPFLTR_IHVDRIVER_ID,
                crate::log::DPFLTR_ERROR_LEVEL,
                concat!($string, "\n\0").as_ptr() as *const i8)
        }
    };

    ($string: expr, $($x:tt)*) => {
        unsafe {
            #[allow(unused_unsafe)]
            $crate::log::DbgPrintEx(
                crate::log::DPFLTR_IHVDRIVER_ID,
                crate::log::DPFLTR_ERROR_LEVEL,
                concat!($string, "\n\0").as_ptr() as *const i8,
                $($x)*)
        }
    };
}
