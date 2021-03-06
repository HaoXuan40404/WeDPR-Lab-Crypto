// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of shared macros.

/// Global flag of enabling debug output.
pub const ENABLE_DEBUG_OUTPUT: bool = true;

/// Prints debug output that can be disabled by setting a global flag.
#[macro_export]
macro_rules! wedpr_println {
            () => ( print!("\n"));
            ($($arg:tt)*) => {
            if $crate::ENABLE_DEBUG_OUTPUT {
                      print!("{}:{}: ", file!(), line!());
                      println!($($arg)*);
            }
     };
}

/// Macros to handle errors and return bool type instead of Result type, which
/// are mainly used to simplify type conversions for Rust FFI.

/// Converts a string to a point if succeeded, otherwise returns false.
#[macro_export]
macro_rules! bytes_to_point {
    ($param:expr) => {
        match bytes_to_point($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_point failed");
                return false;
            },
        }
    };
}

/// Converts a string to a scalar if succeeded, otherwise returns false.
#[macro_export]
macro_rules! bytes_to_scalar {
    ($param:expr) => {
        match bytes_to_scalar($param) {
            Ok(v) => v,
            Err(_) => {
                wedpr_println!("macro string_to_scalar failed");
                return false;
            },
        }
    };
}
