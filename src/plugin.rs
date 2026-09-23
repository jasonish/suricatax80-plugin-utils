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

//! Plugin registration.

/// Define the plugin's `SCPlugin` registration and export
/// `SCPluginRegister()`.
///
/// `name`, `author`, `license` and the optional `version` must be string
/// literals. `version` defaults to the plugin crate's version. `init` is the
/// plugin's `unsafe extern "C" fn()` init function.
///
/// ```ignore
/// suricatax80_plugin_utils::plugin!(
///     name: "example",
///     author: "Example Author",
///     license: "GPL-2.0-only",
///     init: example_init,
/// );
/// ```
#[macro_export]
macro_rules! plugin {
    (
        name: $name:literal,
        $(version: $version:literal,)?
        author: $author:literal,
        license: $license:literal,
        init: $init:path $(,)?
    ) => {
        #[no_mangle]
        pub extern "C" fn SCPluginRegister() -> *mut $crate::SCPlugin {
            static PLUGIN: $crate::SCPlugin = $crate::SCPlugin {
                version: $crate::SC_API_VERSION,
                suricata_version: $crate::SC_PACKAGE_VERSION.as_ptr().cast(),
                name: ::std::concat!($name, "\0").as_ptr().cast(),
                plugin_version: $crate::plugin!(@version $($version)?).as_ptr().cast(),
                license: ::std::concat!($license, "\0").as_ptr().cast(),
                author: ::std::concat!($author, "\0").as_ptr().cast(),
                Init: Some($init),
            };
            (&PLUGIN as *const $crate::SCPlugin).cast_mut()
        }
    };
    (@version) => {
        ::std::concat!(::std::env!("CARGO_PKG_VERSION"), "\0")
    };
    (@version $version:literal) => {
        ::std::concat!($version, "\0")
    };
}
