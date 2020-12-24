// Copyright 2020 WeDPR Lab Project Authors. Licensed under Apache-2.0.

#![cfg(feature = "wedpr_f_vrf_curve25519")]

use libc::c_char;
use std::{ffi::CString, panic, ptr};
use wedpr_l_protos::generated::common;