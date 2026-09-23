/* Copyright (C) 2026 Open Information Security Foundation
 *
 * You can copy, redistribute or modify this Program under the terms of
 * the GNU General Public License version 2 as published by the Free
 * Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * version 2 along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

//! Logging macros, modeled on Suricata's C `SCLog*()` macros and the
//! `suricata-ffi` crate's Rust macros for Suricata 9.
//!
//! The macros record the caller's file, line and function. The log module is
//! the first segment of the caller's module path, which for a plugin is its
//! library crate name.

use std::os::raw::c_int;

use crate::SCLogGetLogLevel;

/// Whether messages at `level` are currently logged by Suricata.
pub fn log_level_enabled(level: c_int) -> bool {
    unsafe { SCLogGetLogLevel() >= level }
}

/// The log module for a `module_path!()`: its first segment, which is the
/// crate name.
#[doc(hidden)]
pub fn __log_module(module_path: &'static str) -> &'static str {
    module_path.split("::").next().unwrap_or(module_path)
}

/// The name of the enclosing function, like C's `__FUNCTION__`.
#[doc(hidden)]
#[macro_export]
macro_rules! __function_name {
    () => {{
        fn __f() {}
        fn __type_name_of<T>(_: T) -> &'static str {
            ::std::any::type_name::<T>()
        }
        let name = __type_name_of(__f);
        &name[..name.len() - 5]
    }};
}

/// Log a formatted message at the given `SC_LOG_*` level.
#[macro_export]
macro_rules! sc_log {
    ($level:expr, $($arg:tt)*) => {{
        let level: ::std::os::raw::c_int = $level;
        if $crate::log_level_enabled(level) {
            $crate::log_message(
                level,
                $crate::__log_module(::std::module_path!()),
                ::std::file!(),
                ::std::line!(),
                $crate::__function_name!(),
                ::std::format!($($arg)*),
            );
        }
    }};
}

/// Log a formatted error message, like C `SCLogError()`.
#[macro_export]
macro_rules! SCLogError {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_ERROR, $($arg)*)
    };
}

/// Log a formatted warning message, like C `SCLogWarning()`.
#[macro_export]
macro_rules! SCLogWarning {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_WARNING, $($arg)*)
    };
}

/// Log a formatted notice message, like C `SCLogNotice()`.
#[macro_export]
macro_rules! SCLogNotice {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_NOTICE, $($arg)*)
    };
}

/// Log a formatted info message, like C `SCLogInfo()`.
#[macro_export]
macro_rules! SCLogInfo {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_INFO, $($arg)*)
    };
}

/// Log a formatted perf message, like C `SCLogPerf()`.
#[macro_export]
macro_rules! SCLogPerf {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_PERF, $($arg)*)
    };
}

/// Log a formatted config message, like C `SCLogConfig()`.
#[macro_export]
macro_rules! SCLogConfig {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_CONFIG, $($arg)*)
    };
}

/// Log a formatted debug message.
///
/// Suricata only logs debug messages when it was built with debug support
/// and run with debug verbosity.
#[macro_export]
macro_rules! SCLogDebug {
    ($($arg:tt)*) => {
        $crate::sc_log!($crate::SC_LOG_DEBUG, $($arg)*)
    };
}

/// Log a formatted error message and exit, like C `FatalError()`.
///
/// This expression has type `!`.
#[macro_export]
macro_rules! SCFatalError {
    ($($arg:tt)*) => {{
        $crate::sc_log!($crate::SC_LOG_ERROR, $($arg)*);
        ::std::process::exit(1)
    }};
}
