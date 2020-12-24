// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

//! Library of macros and functions for FFI of crypto, targeting C/C++
//! compatible architectures (including iOS).

// TODO: Move it to feature flags
#![allow(unused_imports)]
#![allow(dead_code)]

#[cfg(all(feature = "wedpr_f_base64", feature = "wedpr_f_hex"))]
compile_error!("Feature wedpr_base64 and wedpr_hex can not be enable at same time!");

#[cfg(all(not(feature = "wedpr_f_base64"), not(feature = "wedpr_f_hex")))]
compile_error!("Must use feature wedpr_base64 or wedpr_hex!");

#[allow(unused_imports)]
#[macro_use]
extern crate wedpr_ffi_macros;
#[macro_use]
extern crate wedpr_l_macros;

#[macro_use]
extern crate lazy_static;

mod config;
pub mod ecies;
pub mod hash;
pub mod signature;
pub mod vrf;

use protobuf::{self, Message};

// C/C++ FFI: C-style interfaces will be generated.
