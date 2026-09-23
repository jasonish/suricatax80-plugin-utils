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

//! Detection keyword and signature helpers.

use core::ffi::c_void;
use std::ffi::CStr;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int};

use crate::{
    sigmatch_table, DetectEngineCtx, DetectEngineThreadCtx, Packet, SCDetectHelperNewKeywordId,
    SCSigMatchAppendSMToList, SigMatch, SigMatchCtx, Signature, DETECT_SM_LIST_MAX,
};

/// A rule keyword that matches on packets, for [`register_packet_keyword`].
///
/// `name`, `description` and `url` must be nul-terminated byte strings.
pub struct PacketKeyword {
    pub name: &'static [u8],
    pub description: &'static [u8],
    pub url: &'static [u8],
    /// `SIGMATCH_*` flags.
    pub flags: u16,
    pub setup: unsafe extern "C" fn(*mut DetectEngineCtx, *mut Signature, *const c_char) -> c_int,
    pub free: unsafe extern "C" fn(*mut DetectEngineCtx, *mut c_void),
    pub packet_match: unsafe extern "C" fn(
        *mut DetectEngineThreadCtx,
        *mut Packet,
        *const Signature,
        *const SigMatchCtx,
    ) -> c_int,
}

/// Register a packet matching rule keyword, returning its keyword id.
///
/// Suricata 8.0's keyword registration helper has no packet match callback,
/// so this allocates a keyword id and fills in its `sigmatch_table` entry.
/// Must be called during plugin initialization.
pub fn register_packet_keyword(keyword: &PacketKeyword) -> Result<u16, &'static str> {
    let name = CStr::from_bytes_with_nul(keyword.name).map_err(|_| "invalid keyword name")?;
    let description = CStr::from_bytes_with_nul(keyword.description)
        .map_err(|_| "invalid keyword description")?;
    let url = CStr::from_bytes_with_nul(keyword.url).map_err(|_| "invalid keyword URL")?;

    unsafe {
        let id = SCDetectHelperNewKeywordId();
        if id < 0 || id > c_int::from(u16::MAX) {
            return Err("failed to register keyword");
        }
        // Read the table after allocating the id, as that may reallocate it.
        let table = sigmatch_table;
        if table.is_null() {
            return Err("Suricata signature table is unavailable");
        }

        let elmt = &mut *table.add(id as usize);
        elmt.name = name.as_ptr();
        elmt.desc = description.as_ptr();
        elmt.url = url.as_ptr();
        elmt.flags = keyword.flags;
        elmt.Setup = Some(keyword.setup);
        elmt.Free = Some(keyword.free);
        elmt.Match = Some(keyword.packet_match);

        Ok(id as u16)
    }
}

/// Whether the keyword currently being set up on `s` is negated.
///
/// # Safety
///
/// `s` must be null or point to a signature being parsed, as passed to a
/// keyword setup callback.
pub unsafe fn signature_is_negated(s: *const Signature) -> bool {
    if s.is_null() {
        return false;
    }
    let init_data = (*s).init_data;
    !init_data.is_null() && (*init_data).negated
}

/// Iterate over the signature matches of `s` in `list`, such as
/// `DETECT_SM_LIST_MATCH`.
///
/// # Safety
///
/// `s` must be null or point to a signature being parsed, as passed to a
/// keyword setup callback, and the list must not be modified while the
/// iterator is in use.
pub unsafe fn signature_sigmatches<'a>(s: *const Signature, list: c_int) -> SigMatchIter<'a> {
    let mut next = std::ptr::null();
    let valid_list = list >= 0 && (list as usize) < DETECT_SM_LIST_MAX;
    if valid_list && !s.is_null() && !(*s).init_data.is_null() {
        next = (*(*s).init_data).smlists[list as usize].cast_const();
    }
    SigMatchIter {
        next,
        _marker: PhantomData,
    }
}

/// Iterator over a signature's match list, see [`signature_sigmatches`].
pub struct SigMatchIter<'a> {
    next: *const SigMatch,
    _marker: PhantomData<&'a SigMatch>,
}

impl<'a> Iterator for SigMatchIter<'a> {
    type Item = &'a SigMatch;

    fn next(&mut self) -> Option<Self::Item> {
        let sm = unsafe { self.next.as_ref()? };
        self.next = sm.next;
        Some(sm)
    }
}

impl SigMatch {
    /// The keyword id of this match.
    pub fn type_id(&self) -> u16 {
        self.type_
    }

    /// The keyword context of this match.
    pub fn context(&self) -> *const SigMatchCtx {
        self.ctx
    }

    /// The keyword context of this match as a `T`, if this match is for
    /// `keyword_id`.
    ///
    /// # Safety
    ///
    /// Contexts of `keyword_id` must be of type `T`, for example as appended
    /// with [`signature_append_sigmatch`].
    pub unsafe fn context_as<T>(&self, keyword_id: u16) -> Option<&T> {
        if self.type_ == keyword_id {
            self.ctx.cast::<T>().as_ref()
        } else {
            None
        }
    }
}

/// Append a match for `keyword_id` with context `ctx` to `list` of `s`.
///
/// Ownership of `ctx` passes to Suricata, which frees it through the
/// keyword's free callback, such as [`sigmatch_ctx_free::<T>`]. If the match
/// cannot be appended, `ctx` is dropped and an error is returned.
///
/// # Safety
///
/// `de_ctx` and `s` must be the pointers passed to a keyword setup callback.
pub unsafe fn signature_append_sigmatch<T>(
    de_ctx: *mut DetectEngineCtx,
    s: *mut Signature,
    keyword_id: u16,
    ctx: Box<T>,
    list: c_int,
) -> Result<(), &'static str> {
    let ctx = Box::into_raw(ctx);
    let sm = SCSigMatchAppendSMToList(de_ctx, s, keyword_id, ctx.cast::<SigMatchCtx>(), list);
    if sm.is_null() {
        drop(Box::from_raw(ctx));
        return Err("failed to append signature match");
    }
    Ok(())
}

/// A keyword free callback for contexts appended as a `Box<T>`, see
/// [`signature_append_sigmatch`].
///
/// # Safety
///
/// `ptr` must be null or a context of type `T` appended as a `Box<T>`.
pub unsafe extern "C" fn sigmatch_ctx_free<T>(_de_ctx: *mut DetectEngineCtx, ptr: *mut c_void) {
    if !ptr.is_null() {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(Box::from_raw(ptr.cast::<T>()));
        }));
    }
}
