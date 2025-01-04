//! Implementation for Windows 10 and later
//!
//! On Windows 10 and later, ProcessPrng "is the primary interface to the
//! user-mode per-processor PRNGs" and only requires bcryptprimitives.dll,
//! making it a better option than the other Windows RNG APIs:
//!   - BCryptGenRandom: https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
//!     - Requires bcrypt.dll (which loads bcryptprimitives.dll anyway)
//!     - Can cause crashes/hangs as BCrypt accesses the Windows Registry:
//!       https://github.com/rust-lang/rust/issues/99341
//!     - Causes issues inside sandboxed code:
//!       https://issues.chromium.org/issues/40277768
//!   - CryptGenRandom: https://learn.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptgenrandom
//!     - Deprecated and not available on UWP targets
//!     - Requires advapi32.lib/advapi32.dll (in addition to bcryptprimitives.dll)
//!     - Thin wrapper around ProcessPrng
//!   - RtlGenRandom: https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/nf-ntsecapi-rtlgenrandom
//!     - Deprecated and not available on UWP targets
//!     - Requires advapi32.dll (in addition to bcryptprimitives.dll)
//!     - Requires using name "SystemFunction036"
//!     - Thin wrapper around ProcessPrng
//!
//! For more information see the Windows RNG Whitepaper: https://aka.ms/win10rng
use crate::Error;
use core::mem::MaybeUninit;

pub use crate::util::{inner_u32, inner_u64};

// Binding to the Windows.Win32.Security.Cryptography.ProcessPrng API.
#[cfg_attr(
    target_arch = "x86",
    link(
        name = "bcryptprimitives",
        kind = "raw-dylib",
        import_name_type = "undecorated"
    )
)]
#[cfg_attr(
    not(target_arch = "x86"),
    link(name = "bcryptprimitives", kind = "raw-dylib")
)]
extern "system" {
    fn ProcessPrng(pbdata: *mut u8, cbdata: usize) -> i32;
}

pub fn fill_inner(dest: &mut [MaybeUninit<u8>]) -> Result<(), Error> {
    // Since Windows 10, calls to the user-mode RNG are guaranteed
    // to never fail during runtime (rare windows W); this function
    // will only ever return success.
    // See the bottom of page 6 of the aforementioned Windows RNG
    // whitepaper for more information.
    unsafe { ProcessPrng(dest.as_mut_ptr().cast(), dest.len()) };
    Ok(())
}
