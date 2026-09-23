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

//! Typed flow and thread storage, modeled on `FlowStorage<T>` and
//! `ThreadStorage<T>` in the `suricata-ffi` crate for Suricata 9.

use core::ffi::c_void;
use std::ffi::CString;
use std::marker::PhantomData;
use std::mem;

use crate::{
    Flow, FlowGetStorageById, FlowSetStorageById, FlowStorageId, FlowStorageRegister,
    ThreadGetStorageById, ThreadSetStorageById, ThreadStorageId, ThreadStorageRegister,
    ThreadVars,
};

/// Free callback for storage holding a `Box<T>`.
unsafe extern "C" fn free_boxed<T>(ptr: *mut c_void) {
    if !ptr.is_null() {
        // The drop runs across an FFI boundary, so guard against unwinding
        // into C if `T`'s `Drop` panics.
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            drop(Box::from_raw(ptr.cast::<T>()));
        }));
    }
}

/// Convert a storage name for registration. Suricata keeps the name pointer
/// for the lifetime of the process, so the returned pointer is leaked.
fn leak_name(name: &str, err: &'static str) -> Result<*const std::os::raw::c_char, &'static str> {
    let name = CString::new(name).map_err(|_| err)?;
    Ok(name.into_raw().cast_const())
}

/// A typed handle to a per-flow storage slot.
///
/// Values are stored as a `Box<T>` owned by Suricata's flow storage and are
/// dropped automatically when the flow's storage is freed.
///
/// The handle only holds the storage id, so it is `Copy`, `Send` and `Sync`
/// regardless of `T`, and can be kept in a static.
pub struct FlowStorage<T> {
    id: FlowStorageId,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Clone for FlowStorage<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for FlowStorage<T> {}

impl<T: Send + 'static> FlowStorage<T> {
    /// Register a new flow storage slot for values of type `T`.
    ///
    /// `name` must be unique among registered flow storage. Registration has
    /// to happen during plugin initialization.
    pub fn register(name: &str) -> Result<Self, &'static str> {
        let name = leak_name(name, "flow storage name contains a nul byte")?;
        let id = unsafe {
            FlowStorageRegister(
                name,
                mem::size_of::<*mut c_void>() as u32,
                None,
                Some(free_boxed::<T>),
            )
        };
        if id.id < 0 {
            return Err("Failed to register flow storage");
        }
        Ok(Self {
            id,
            _marker: PhantomData,
        })
    }

    /// The raw storage id.
    pub fn id(&self) -> FlowStorageId {
        self.id
    }

    /// Return a reference to the value stored for `f`, if any.
    pub fn get<'f>(&self, f: &'f Flow) -> Option<&'f T> {
        let ptr = unsafe { FlowGetStorageById(f, self.id) };
        unsafe { ptr.cast::<T>().as_ref() }
    }

    /// Return a mutable reference to the value stored for `f`, if any.
    pub fn get_mut<'f>(&self, f: &'f mut Flow) -> Option<&'f mut T> {
        let ptr = unsafe { FlowGetStorageById(f, self.id) };
        unsafe { ptr.cast::<T>().as_mut() }
    }

    /// Store `value` for `f`, dropping any value already stored.
    pub fn set(&self, f: &mut Flow, value: T) -> Result<(), &'static str> {
        let old = unsafe { FlowGetStorageById(f, self.id) };
        let ptr = Box::into_raw(Box::new(value));
        if unsafe { FlowSetStorageById(f, self.id, ptr.cast()) } != 0 {
            unsafe { drop(Box::from_raw(ptr)) };
            return Err("Failed to set flow storage");
        }
        unsafe { free_boxed::<T>(old) };
        Ok(())
    }

    /// Return a mutable reference to the value stored for `f`, inserting the
    /// value produced by `init` if none is present yet.
    pub fn get_or_insert_with<'f>(
        &self,
        f: &'f mut Flow,
        init: impl FnOnce() -> T,
    ) -> Result<&'f mut T, &'static str> {
        let ptr = unsafe { FlowGetStorageById(f, self.id) };
        if !ptr.is_null() {
            return Ok(unsafe { &mut *ptr.cast::<T>() });
        }
        let ptr = Box::into_raw(Box::new(init()));
        if unsafe { FlowSetStorageById(f, self.id, ptr.cast()) } != 0 {
            unsafe { drop(Box::from_raw(ptr)) };
            return Err("Failed to set flow storage");
        }
        Ok(unsafe { &mut *ptr })
    }
}

/// A typed handle to a per-thread storage slot.
///
/// Values are stored as a `Box<T>` owned by Suricata's thread storage and are
/// dropped automatically when the thread's storage is freed.
///
/// The handle only holds the storage id, so it is `Copy`, `Send` and `Sync`
/// regardless of `T`, and can be kept in a static.
pub struct ThreadStorage<T> {
    id: ThreadStorageId,
    _marker: PhantomData<fn() -> T>,
}

impl<T> Clone for ThreadStorage<T> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T> Copy for ThreadStorage<T> {}

impl<T: Send + 'static> ThreadStorage<T> {
    /// Register a new thread storage slot for values of type `T`.
    ///
    /// `name` must be unique among registered thread storage. Registration
    /// has to happen during plugin initialization.
    pub fn register(name: &str) -> Result<Self, &'static str> {
        let name = leak_name(name, "thread storage name contains a nul byte")?;
        let id = unsafe {
            ThreadStorageRegister(
                name,
                mem::size_of::<*mut c_void>() as u32,
                None,
                Some(free_boxed::<T>),
            )
        };
        if id.id < 0 {
            return Err("Failed to register thread storage");
        }
        Ok(Self {
            id,
            _marker: PhantomData,
        })
    }

    /// The raw storage id.
    pub fn id(&self) -> ThreadStorageId {
        self.id
    }

    /// Return a reference to the value stored for `tv`, if any.
    pub fn get<'t>(&self, tv: &'t ThreadVars) -> Option<&'t T> {
        let ptr = unsafe { ThreadGetStorageById(tv, self.id) };
        unsafe { ptr.cast::<T>().as_ref() }
    }

    /// Return a mutable reference to the value stored for `tv`, if any.
    pub fn get_mut<'t>(&self, tv: &'t mut ThreadVars) -> Option<&'t mut T> {
        let ptr = unsafe { ThreadGetStorageById(tv, self.id) };
        unsafe { ptr.cast::<T>().as_mut() }
    }

    /// Store `value` for `tv`, dropping any value already stored.
    pub fn set(&self, tv: &mut ThreadVars, value: T) -> Result<(), &'static str> {
        let old = unsafe { ThreadGetStorageById(tv, self.id) };
        let ptr = Box::into_raw(Box::new(value));
        if unsafe { ThreadSetStorageById(tv, self.id, ptr.cast()) } != 0 {
            unsafe { drop(Box::from_raw(ptr)) };
            return Err("Failed to set thread storage");
        }
        unsafe { free_boxed::<T>(old) };
        Ok(())
    }

    /// Return a mutable reference to the value stored for `tv`, inserting the
    /// value produced by `init` if none is present yet.
    pub fn get_or_insert_with<'t>(
        &self,
        tv: &'t mut ThreadVars,
        init: impl FnOnce() -> T,
    ) -> Result<&'t mut T, &'static str> {
        let ptr = unsafe { ThreadGetStorageById(tv, self.id) };
        if !ptr.is_null() {
            return Ok(unsafe { &mut *ptr.cast::<T>() });
        }
        let ptr = Box::into_raw(Box::new(init()));
        if unsafe { ThreadSetStorageById(tv, self.id, ptr.cast()) } != 0 {
            unsafe { drop(Box::from_raw(ptr)) };
            return Err("Failed to set thread storage");
        }
        Ok(unsafe { &mut *ptr })
    }
}
