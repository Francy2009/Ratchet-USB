// C ABI for the vendored Signal SPQR implementation. Secret-bearing buffers
// that cross the boundary are owned by this library and must be freed with
// ratchet_spqr_free, which locks, zeroizes and releases them.
//
// What this protects, and what it does not:
//
//   * Inputs from C++ are copied once into a Zeroizing<Vec<u8>> and wiped on
//     every path, including early error returns.
//   * Outputs are copied into an exact-size boxed slice and the source vector
//     is zeroized, so a shrink-reallocation cannot leave a second copy of a key
//     on the heap. The box is best-effort mlocked so its pages do not reach
//     swap, and it is zeroized when ratchet_spqr_free drops it.
//   * mlock can fail for entirely ordinary reasons -- RLIMIT_MEMLOCK, a
//     container without CAP_IPC_LOCK, a platform where it is unavailable. The
//     failure is deliberately non-fatal: the buffer is still wiped on release.
//   * The vendored crate still holds working state and intermediate values in
//     its own heap allocations while it runs. This bridge reduces the number
//     and lifetime of copies that cross the boundary; it does not and cannot
//     claim that no copy of a secret ever escapes. A compromised host can read
//     any of it.

use std::panic::{catch_unwind, AssertUnwindSafe};
use zeroize::{Zeroize, Zeroizing};

const MAX_STATE: usize = 8 * 1024 * 1024;
const MAX_MESSAGE: usize = 1024 * 1024;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RatchetSpqrBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

impl Default for RatchetSpqrBuffer {
    fn default() -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
        }
    }
}

// Copies the caller's buffer into an owned, zeroizing vector.
//
// Returning a borrowed slice would need a lifetime the caller cannot justify
// from a raw pointer: a safe function must not hand out a reference whose
// lifetime it does not control. An owned copy keeps the signature honest, and
// the state and message arguments were already copied by their callers anyway.
fn input(ptr: *const u8, len: usize, max: usize) -> Result<Zeroizing<Vec<u8>>, ()> {
    if len > max {
        return Err(());
    }
    if len == 0 {
        return Ok(Zeroizing::new(Vec::new()));
    }
    if ptr.is_null() {
        return Err(());
    }
    // SAFETY: the C++ caller promises the input remains live for this call.
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    Ok(Zeroizing::new(slice.to_vec()))
}

// Copies `bytes` into an exact-size boxed slice, locks it into RAM when the OS
// allows, and hands ownership to the caller.
//
// The copy is deliberate. `Vec::into_boxed_slice` shrinks the vector to its
// length, and when the capacity was larger that reallocation frees the old
// block without wiping it -- key material left on the heap for the allocator to
// hand to somebody else. Allocating the exact size first and copying into it
// keeps the only freed block the source vector, which the caller has wrapped in
// Zeroizing and which is therefore wiped.
unsafe fn output(ptr: *mut RatchetSpqrBuffer, bytes: &[u8]) {
    if bytes.is_empty() {
        // A zero-length allocation has no meaningful pointer to free later;
        // represent it as the same null buffer a missing output uses.
        *ptr = RatchetSpqrBuffer::default();
        return;
    }
    let mut boxed = vec![0u8; bytes.len()].into_boxed_slice();
    boxed.copy_from_slice(bytes);
    // Best effort. mlock is page-granular and may fail on limits or in a
    // container; either way the bytes are still wiped when the buffer is freed.
    let _ = libc::mlock(boxed.as_ptr() as *const libc::c_void, boxed.len());
    let buffer = RatchetSpqrBuffer {
        ptr: boxed.as_mut_ptr(),
        len: boxed.len(),
    };
    std::mem::forget(boxed);
    *ptr = buffer;
}

#[no_mangle]
pub extern "C" fn ratchet_spqr_init(
    initiator: bool,
    auth_key: *const u8,
    auth_key_len: usize,
    out_state: *mut RatchetSpqrBuffer,
) -> i32 {
    if out_state.is_null() {
        return -1;
    }
    unsafe { *out_state = RatchetSpqrBuffer::default() };
    let result = catch_unwind(AssertUnwindSafe(|| {
        let key = input(auth_key, auth_key_len, 32)?;
        if key.len() != 32 {
            return Err(());
        }
        let state = Zeroizing::new(
            spqr::initial_state(spqr::Params {
                direction: if initiator {
                    spqr::Direction::A2B
                } else {
                    spqr::Direction::B2A
                },
                version: spqr::Version::V1,
                min_version: spqr::Version::V1,
                auth_key: key.as_slice(),
                chain_params: spqr::ChainParams {
                    max_jump: 1000,
                    max_ooo_keys: 1000,
                },
            })
            .map_err(|_| ())?,
        );
        if state.len() > MAX_STATE {
            return Err(());
        }
        unsafe { output(out_state, &state) };
        Ok(())
    }));
    if matches!(result, Ok(Ok(()))) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn ratchet_spqr_send(
    state_ptr: *const u8,
    state_len: usize,
    out_state: *mut RatchetSpqrBuffer,
    out_message: *mut RatchetSpqrBuffer,
    out_key: *mut RatchetSpqrBuffer,
) -> i32 {
    if out_state.is_null() || out_message.is_null() || out_key.is_null() {
        return -1;
    }
    unsafe {
        *out_state = RatchetSpqrBuffer::default();
        *out_message = RatchetSpqrBuffer::default();
        *out_key = RatchetSpqrBuffer::default();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = input(state_ptr, state_len, MAX_STATE)?;
        let sent = spqr::send(&state, &mut rand::rng()).map_err(|_| ())?;
        // Bind the outputs in Zeroizing before any check, so every early return
        // wipes them rather than dropping plain Vecs on the floor.
        let key = Zeroizing::new(sent.key.ok_or(())?);
        let next_state = Zeroizing::new(sent.state);
        let message = Zeroizing::new(sent.msg);
        if key.len() != 32 || next_state.len() > MAX_STATE || message.len() > MAX_MESSAGE {
            return Err(());
        }
        unsafe {
            output(out_state, &next_state);
            output(out_message, &message);
            output(out_key, &key);
        }
        Ok(())
    }));
    if matches!(result, Ok(Ok(()))) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn ratchet_spqr_recv(
    state_ptr: *const u8,
    state_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    out_state: *mut RatchetSpqrBuffer,
    out_key: *mut RatchetSpqrBuffer,
) -> i32 {
    if out_state.is_null() || out_key.is_null() {
        return -1;
    }
    unsafe {
        *out_state = RatchetSpqrBuffer::default();
        *out_key = RatchetSpqrBuffer::default();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        let state = input(state_ptr, state_len, MAX_STATE)?;
        let message = input(message_ptr, message_len, MAX_MESSAGE)?;
        let received = spqr::recv(&state, &message).map_err(|_| ())?;
        let key = Zeroizing::new(received.key.ok_or(())?);
        let next_state = Zeroizing::new(received.state);
        if key.len() != 32 || next_state.len() > MAX_STATE {
            return Err(());
        }
        unsafe {
            output(out_state, &next_state);
            output(out_key, &key);
        }
        Ok(())
    }));
    if matches!(result, Ok(Ok(()))) { 0 } else { -1 }
}

#[no_mangle]
pub extern "C" fn ratchet_spqr_free(buffer: RatchetSpqrBuffer) {
    if buffer.ptr.is_null() {
        return;
    }
    // SAFETY: the buffer came from output() and ownership is returned once.
    let ptr = std::ptr::slice_from_raw_parts_mut(buffer.ptr, buffer.len);
    let mut bytes = unsafe { Box::from_raw(ptr) };
    // Release the lock (a no-op if mlock never took) before wiping.
    let _ = unsafe { libc::munlock(bytes.as_ptr() as *const libc::c_void, bytes.len()) };
    bytes.zeroize();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn take(buffer: RatchetSpqrBuffer) -> Vec<u8> {
        let bytes = unsafe { std::slice::from_raw_parts(buffer.ptr, buffer.len) }.to_vec();
        ratchet_spqr_free(buffer);
        bytes
    }

    #[test]
    fn both_directions_agree_on_message_keys() {
        let auth_key = [17u8; 32];
        let mut a = RatchetSpqrBuffer::default();
        let mut b = RatchetSpqrBuffer::default();
        assert_eq!(ratchet_spqr_init(true, auth_key.as_ptr(), 32, &mut a), 0);
        assert_eq!(ratchet_spqr_init(false, auth_key.as_ptr(), 32, &mut b), 0);
        let mut a = take(a);
        let mut b = take(b);
        for turn in 0..8 {
            let (sender, receiver) = if turn % 2 == 0 { (&mut a, &mut b) } else { (&mut b, &mut a) };
            let mut next = RatchetSpqrBuffer::default();
            let mut msg = RatchetSpqrBuffer::default();
            let mut key = RatchetSpqrBuffer::default();
            assert_eq!(ratchet_spqr_send(sender.as_ptr(), sender.len(), &mut next, &mut msg, &mut key), 0);
            *sender = take(next);
            let msg = take(msg);
            let send_key = take(key);
            assert_eq!(send_key.len(), 32);
            let mut next = RatchetSpqrBuffer::default();
            let mut key = RatchetSpqrBuffer::default();
            assert_eq!(ratchet_spqr_recv(receiver.as_ptr(), receiver.len(), msg.as_ptr(), msg.len(), &mut next, &mut key), 0);
            *receiver = take(next);
            assert_eq!(send_key, take(key));
        }
    }
}
