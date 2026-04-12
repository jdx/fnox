//! Dynamic libusb loading for YubiKey HMAC-SHA1 challenge-response.
//!
//! This module replaces the `yubico_manager` crate with a minimal implementation
//! that loads libusb at runtime via `libloading`. If libusb is not installed,
//! the binary still starts — the YubiKey provider returns a clear error when used.
//!
//! The YubiKey OTP frame protocol and USB HID report handling are based on
//! yubico_manager (https://github.com/wisespace-io/yubico-rs), licensed under
//! MIT OR Apache-2.0.

use std::ptr;
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{FnoxError, Result};

const VENDOR_ID: u16 = 0x1050;

// OTP-capable YubiKey product IDs, sourced from yubikey-manager (ykman).
// Only PIDs with the OTP interface enabled support HMAC-SHA1 challenge-response.
// PIDs without OTP (e.g. 0x0112 NEO CCID, 0x0402 FIDO, 0x0406 FIDO+CCID) are excluded.
const OTP_PRODUCT_IDS: &[u16] = &[
    0x0010, // YubiKey Standard (v1/v2) — OTP
    0x0110, // YubiKey NEO — OTP
    0x0111, // YubiKey NEO — OTP+CCID
    0x0114, // YubiKey NEO — OTP+FIDO
    0x0116, // YubiKey NEO — OTP+FIDO+CCID
    0x0401, // YubiKey 4/5 — OTP
    0x0403, // YubiKey 4/5 — OTP+FIDO
    0x0405, // YubiKey 4/5 — OTP+CCID
    0x0407, // YubiKey 4/5 — OTP+FIDO+CCID
    0x0410, // YubiKey Plus — OTP+FIDO
];

// HID constants
const HID_GET_REPORT: u8 = 0x01;
const HID_SET_REPORT: u8 = 0x09;
const REPORT_TYPE_FEATURE: u16 = 0x03;

// USB request type components
const REQTYPE_IN_CLASS_INTERFACE: u8 = 0x80 | 0x20 | 0x01; // Direction::In | RequestType::Class | Recipient::Interface
const REQTYPE_OUT_CLASS_INTERFACE: u8 = 0x20 | 0x01; // Direction::Out | RequestType::Class | Recipient::Interface

// Frame constants
const DATA_SIZE: usize = 64;
const FRAME_SIZE: usize = 70;

// CRC constants
const CRC_PRESET: u16 = 0xFFFF;
const CRC_POLYNOMIAL: u16 = 0x8408;
const CRC_RESIDUAL_OK: u16 = 0xF0B8;

// Flags
const SLOT_WRITE_FLAG: u8 = 0x80;
const RESP_PENDING_FLAG: u8 = 0x40;

// Commands
const CHALLENGE_HMAC1: u8 = 0x30;
const CHALLENGE_HMAC2: u8 = 0x38;

// Timeout for wait_for polling loop
const WAIT_TIMEOUT: Duration = Duration::from_secs(15);

// Opaque libusb types
enum LibusbContext {}
enum LibusbDevice {}
enum LibusbDeviceHandle {}

#[repr(C)]
#[derive(Default)]
struct LibusbDeviceDescriptor {
    b_length: u8,
    b_descriptor_type: u8,
    bcd_usb: u16,
    b_device_class: u8,
    b_device_sub_class: u8,
    b_device_protocol: u8,
    b_max_packet_size0: u8,
    id_vendor: u16,
    id_product: u16,
    bcd_device: u16,
    i_manufacturer: u8,
    i_product: u8,
    i_serial_number: u8,
    b_num_configurations: u8,
}

/// Loaded libusb function pointers.
struct LibUsb {
    _lib: libloading::Library,
    init: unsafe extern "C" fn(*mut *mut LibusbContext) -> i32,
    exit: unsafe extern "C" fn(*mut LibusbContext),
    get_device_list: unsafe extern "C" fn(*mut LibusbContext, *mut *mut *mut LibusbDevice) -> isize,
    free_device_list: unsafe extern "C" fn(*mut *mut LibusbDevice, i32),
    get_device_descriptor:
        unsafe extern "C" fn(*mut LibusbDevice, *mut LibusbDeviceDescriptor) -> i32,
    open: unsafe extern "C" fn(*mut LibusbDevice, *mut *mut LibusbDeviceHandle) -> i32,
    close: unsafe extern "C" fn(*mut LibusbDeviceHandle),
    control_transfer:
        unsafe extern "C" fn(*mut LibusbDeviceHandle, u8, u8, u16, u16, *mut u8, u16, u32) -> i32,
    kernel_driver_active: unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32,
    detach_kernel_driver: unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32,
    attach_kernel_driver: unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32,
    claim_interface: unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32,
    release_interface: unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32,
}

impl LibUsb {
    fn load() -> Result<Self> {
        let lib_names: &[&str] = if cfg!(target_os = "macos") {
            &[
                "libusb-1.0.dylib",
                "libusb-1.0.0.dylib",
                "/opt/homebrew/lib/libusb-1.0.0.dylib",
                "/usr/local/lib/libusb-1.0.0.dylib",
            ]
        } else if cfg!(target_os = "windows") {
            &[
                "libusb-1.0.dll",
                "C:\\Program Files\\LibUSB-Win32\\bin\\amd64\\libusb-1.0.dll",
                "C:\\Program Files\\libusb\\bin\\libusb-1.0.dll",
                "C:\\vcpkg\\installed\\x64-windows\\bin\\libusb-1.0.dll",
            ]
        } else {
            // Linux / other Unix
            &["libusb-1.0.so", "libusb-1.0.so.0"]
        };

        let lib = lib_names
            .iter()
            .find_map(|name| unsafe { libloading::Library::new(*name).ok() })
            .ok_or_else(|| {
                let install_hint = if cfg!(target_os = "macos") {
                    "Install it with: brew install libusb"
                } else if cfg!(target_os = "windows") {
                    "Install libusb from https://libusb.info"
                } else {
                    "Install it with: sudo apt install libusb-1.0-0 (Debian/Ubuntu) or sudo dnf install libusb1 (Fedora)"
                };
                FnoxError::Provider(format!(
                    "YubiKey support requires libusb, but it is not installed. {install_hint}"
                ))
            })?;

        unsafe {
            let init = *lib
                .get::<unsafe extern "C" fn(*mut *mut LibusbContext) -> i32>(b"libusb_init\0")
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let exit = *lib
                .get::<unsafe extern "C" fn(*mut LibusbContext)>(b"libusb_exit\0")
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let get_device_list = *lib
                .get::<unsafe extern "C" fn(*mut LibusbContext, *mut *mut *mut LibusbDevice) -> isize>(
                    b"libusb_get_device_list\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let free_device_list = *lib
                .get::<unsafe extern "C" fn(*mut *mut LibusbDevice, i32)>(
                    b"libusb_free_device_list\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let get_device_descriptor = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDevice, *mut LibusbDeviceDescriptor) -> i32>(
                    b"libusb_get_device_descriptor\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let open = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDevice, *mut *mut LibusbDeviceHandle) -> i32>(
                    b"libusb_open\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let close = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle)>(b"libusb_close\0")
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let control_transfer = *lib
                .get::<unsafe extern "C" fn(
                    *mut LibusbDeviceHandle,
                    u8,
                    u8,
                    u16,
                    u16,
                    *mut u8,
                    u16,
                    u32,
                ) -> i32>(b"libusb_control_transfer\0")
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let kernel_driver_active = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32>(
                    b"libusb_kernel_driver_active\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let detach_kernel_driver = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32>(
                    b"libusb_detach_kernel_driver\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let attach_kernel_driver = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32>(
                    b"libusb_attach_kernel_driver\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let claim_interface = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32>(
                    b"libusb_claim_interface\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;
            let release_interface = *lib
                .get::<unsafe extern "C" fn(*mut LibusbDeviceHandle, i32) -> i32>(
                    b"libusb_release_interface\0",
                )
                .map_err(|e| FnoxError::Provider(format!("libusb symbol error: {e}")))?;

            Ok(LibUsb {
                _lib: lib,
                init,
                exit,
                get_device_list,
                free_device_list,
                get_device_descriptor,
                open,
                close,
                control_transfer,
                kernel_driver_active,
                detach_kernel_driver,
                attach_kernel_driver,
                claim_interface,
                release_interface,
            })
        }
    }
}

/// RAII wrapper for a libusb context.
struct UsbContext {
    lib: LibUsb,
    ctx: *mut LibusbContext,
}

impl UsbContext {
    fn new() -> Result<Self> {
        let lib = LibUsb::load()?;
        let mut ctx: *mut LibusbContext = ptr::null_mut();
        let rc = unsafe { (lib.init)(&mut ctx) };
        if rc < 0 {
            return Err(FnoxError::Provider(format!(
                "libusb_init failed (error {rc})"
            )));
        }
        Ok(UsbContext { lib, ctx })
    }

    /// Find the first OTP-capable YubiKey and open it in a single enumeration pass.
    /// This avoids a TOCTOU gap between finding and opening the device.
    fn find_and_open(&self) -> Result<DeviceHandle<'_>> {
        let mut list: *mut *mut LibusbDevice = ptr::null_mut();
        let count = unsafe { (self.lib.get_device_list)(self.ctx, &mut list) };
        if count < 0 {
            return Err(FnoxError::Provider(
                "Failed to enumerate USB devices".to_string(),
            ));
        }

        let result = (|| {
            let mut found_non_otp = false;
            for i in 0..count as usize {
                let dev = unsafe { *list.add(i) };
                if dev.is_null() {
                    break;
                }
                let mut desc = LibusbDeviceDescriptor::default();
                let rc = unsafe { (self.lib.get_device_descriptor)(dev, &mut desc) };
                if rc < 0 {
                    continue;
                }
                if desc.id_vendor == VENDOR_ID {
                    if !OTP_PRODUCT_IDS.contains(&desc.id_product) {
                        found_non_otp = true;
                        continue;
                    }

                    let mut handle: *mut LibusbDeviceHandle = ptr::null_mut();
                    let rc = unsafe { (self.lib.open)(dev, &mut handle) };
                    if rc < 0 {
                        return Err(FnoxError::Provider(format!(
                            "Failed to open YubiKey (libusb error {rc})"
                        )));
                    }

                    // On Linux, detach the kernel HID driver and claim the interface.
                    // Without this, control transfers fail with LIBUSB_ERROR_ACCESS (-3)
                    // or LIBUSB_ERROR_BUSY (-6) because the kernel driver owns the device.
                    // On macOS/Windows this is not needed (returns LIBUSB_ERROR_NOT_SUPPORTED).
                    let mut driver_was_detached = false;
                    unsafe {
                        let active = (self.lib.kernel_driver_active)(handle, 0);
                        if active == 1 {
                            let rc = (self.lib.detach_kernel_driver)(handle, 0);
                            if rc < 0 && rc != -12 {
                                // -12 = LIBUSB_ERROR_NOT_SUPPORTED (macOS/Windows)
                                (self.lib.close)(handle);
                                return Err(FnoxError::Provider(format!(
                                    "Failed to detach kernel driver from YubiKey (libusb error {rc})"
                                )));
                            }
                            if rc == 0 {
                                driver_was_detached = true;
                            }
                        }
                        let rc = (self.lib.claim_interface)(handle, 0);
                        if rc < 0 && rc != -12 {
                            if driver_was_detached {
                                (self.lib.attach_kernel_driver)(handle, 0);
                            }
                            (self.lib.close)(handle);
                            return Err(FnoxError::Provider(format!(
                                "Failed to claim YubiKey interface (libusb error {rc})"
                            )));
                        }
                    }

                    return Ok(DeviceHandle {
                        lib: &self.lib,
                        handle,
                        driver_was_detached,
                    });
                }
            }
            if found_non_otp {
                Err(FnoxError::Provider(
                    "Found a Yubico device, but it does not support OTP/HMAC-SHA1. \
                     FIDO2-only Security Keys are not supported for this provider."
                        .to_string(),
                ))
            } else {
                Err(FnoxError::Provider(
                    "No YubiKey found. Make sure it is plugged in.".to_string(),
                ))
            }
        })();

        unsafe { (self.lib.free_device_list)(list, 1) };
        result
    }
}

impl Drop for UsbContext {
    fn drop(&mut self) {
        unsafe { (self.lib.exit)(self.ctx) };
    }
}

/// RAII wrapper for a libusb device handle.
struct DeviceHandle<'a> {
    lib: &'a LibUsb,
    handle: *mut LibusbDeviceHandle,
    driver_was_detached: bool,
}

impl DeviceHandle<'_> {
    fn read_report(&self, buf: &mut [u8; 8]) -> Result<usize> {
        let value = REPORT_TYPE_FEATURE << 8;
        let rc = unsafe {
            (self.lib.control_transfer)(
                self.handle,
                REQTYPE_IN_CLASS_INTERFACE,
                HID_GET_REPORT,
                value,
                0,
                buf.as_mut_ptr(),
                8,
                2000,
            )
        };
        if rc < 0 {
            return Err(FnoxError::Provider(format!(
                "YubiKey USB read failed (error {rc})"
            )));
        }
        Ok(rc as usize)
    }

    fn write_packet(&self, packet: &[u8; 8]) -> Result<()> {
        let value = REPORT_TYPE_FEATURE << 8;
        // Need a mutable copy for the FFI call
        let mut data = *packet;
        let rc = unsafe {
            (self.lib.control_transfer)(
                self.handle,
                REQTYPE_OUT_CLASS_INTERFACE,
                HID_SET_REPORT,
                value,
                0,
                data.as_mut_ptr(),
                8,
                2000,
            )
        };
        if rc != 8 {
            return Err(FnoxError::Provider(format!(
                "YubiKey USB write failed (wrote {rc}, expected 8)"
            )));
        }
        Ok(())
    }

    fn wait_for<F: Fn(u8) -> bool>(&self, predicate: F) -> Result<[u8; 8]> {
        let deadline = Instant::now() + WAIT_TIMEOUT;
        let mut buf = [0u8; 8];
        loop {
            if Instant::now() > deadline {
                return Err(FnoxError::Provider(
                    "Timed out waiting for YubiKey response (is the key plugged in?)".to_string(),
                ));
            }
            self.read_report(&mut buf)?;
            let flags = buf[7];
            if predicate(flags) {
                return Ok(buf);
            }
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn write_frame(&self, frame: &[u8; FRAME_SIZE]) -> Result<()> {
        let mut offset = 0;
        let mut seq: u8 = 0;

        while offset < FRAME_SIZE {
            let remaining = FRAME_SIZE - offset;
            let chunk_len = remaining.min(7);
            let mut packet = [0u8; 8];
            packet[..chunk_len].copy_from_slice(&frame[offset..offset + chunk_len]);
            let is_first = seq == 0;
            let is_last = offset + chunk_len >= FRAME_SIZE;
            let is_nonzero = packet[..7].iter().any(|&b| b != 0);

            // NOTE: The YubiKey firmware treats undelivered zero-payload chunks as
            // zero-filled. This optimization matches yubico_manager behavior and has
            // been stable across all firmware versions since YubiKey 2.x.
            if is_first || is_last || is_nonzero {
                packet[7] = SLOT_WRITE_FLAG | seq;
                self.wait_for(|f| f & SLOT_WRITE_FLAG == 0)?;
                self.write_packet(&packet)?;
            }

            offset += 7;
            seq += 1;
        }
        Ok(())
    }

    fn read_response(&self, response: &mut [u8; 36]) -> Result<usize> {
        // Wait for RESP_PENDING_FLAG, capturing first 8 bytes
        let first = self.wait_for(|f| f & RESP_PENDING_FLAG != 0)?;
        response[..8].copy_from_slice(&first);
        let mut r0: usize = 7;

        loop {
            if r0 >= 36 {
                break;
            }
            let mut buf = [0u8; 8];
            let n = self.read_report(&mut buf)?;
            if n < 8 {
                return Err(FnoxError::Provider(format!(
                    "YubiKey returned a short HID report ({n} bytes, expected 8); \
                     is the key still plugged in?"
                )));
            }
            let end = (r0 + 8).min(36);
            let copy_len = end - r0;
            response[r0..r0 + copy_len].copy_from_slice(&buf[..copy_len]);

            let flags = buf[7];
            if flags & RESP_PENDING_FLAG != 0 {
                let seq = flags & 0x1F;
                if r0 > 0 && seq == 0 {
                    break;
                }
            } else {
                break;
            }
            r0 += 7;
        }

        // Send write_reset
        let mut reset_packet = [0u8; 8];
        reset_packet[7] = 0x8F;
        self.write_packet(&reset_packet)?;
        self.wait_for(|f| f & SLOT_WRITE_FLAG == 0)?;

        Ok(r0)
    }
}

impl Drop for DeviceHandle<'_> {
    fn drop(&mut self) {
        unsafe {
            (self.lib.release_interface)(self.handle, 0);
            if self.driver_was_detached {
                (self.lib.attach_kernel_driver)(self.handle, 0);
            }
            (self.lib.close)(self.handle);
        }
    }
}

// Ensure the handle types are Send (the raw pointers are only accessed from one thread).
unsafe impl Send for UsbContext {}

fn crc16(data: &[u8]) -> u16 {
    let mut crc = CRC_PRESET;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            let j = crc & 1;
            crc >>= 1;
            if j != 0 {
                crc ^= CRC_POLYNOMIAL;
            }
        }
    }
    crc
}

fn build_frame(payload: &[u8; DATA_SIZE], command: u8) -> [u8; FRAME_SIZE] {
    let mut frame = [0u8; FRAME_SIZE];
    frame[..DATA_SIZE].copy_from_slice(payload);
    frame[DATA_SIZE] = command;
    // CRC covers payload + command byte (65 bytes), per YubiKey protocol spec
    let crc = crc16(&frame[..DATA_SIZE + 1]).to_le_bytes();
    frame[DATA_SIZE + 1] = crc[0];
    frame[DATA_SIZE + 2] = crc[1];
    // filler bytes remain 0
    frame
}

/// Perform HMAC-SHA1 challenge-response with a YubiKey.
///
/// Finds the first OTP-capable YubiKey, opens it, and performs the challenge
/// in a single libusb context — no TOCTOU gap between discovery and use.
///
/// `challenge`: the raw challenge bytes (up to 64 bytes)
/// `slot`: 1 or 2
///
/// Returns the 20-byte HMAC-SHA1 response.
pub fn challenge_response_hmac(challenge: &[u8], slot: u8) -> Result<[u8; 20]> {
    if slot != 1 && slot != 2 {
        return Err(FnoxError::Provider(format!(
            "Invalid YubiKey slot {slot}, must be 1 or 2"
        )));
    }

    let ctx = UsbContext::new()?;
    let handle = ctx.find_and_open()?;

    let mut payload = [0u8; DATA_SIZE];
    let len = challenge.len().min(DATA_SIZE);
    payload[..len].copy_from_slice(&challenge[..len]);

    let command = match slot {
        1 => CHALLENGE_HMAC1,
        _ => CHALLENGE_HMAC2,
    };

    let frame = build_frame(&payload, command);

    // Wait for device ready
    handle.wait_for(|f| f & SLOT_WRITE_FLAG == 0)?;

    // Send challenge
    handle.write_frame(&frame)?;

    // Read response
    let mut response = [0u8; 36];
    handle.read_response(&mut response)?;

    // Verify CRC
    if crc16(&response[..22]) != CRC_RESIDUAL_OK {
        return Err(FnoxError::Provider(
            "YubiKey HMAC response CRC check failed".to_string(),
        ));
    }

    let mut hmac = [0u8; 20];
    hmac.copy_from_slice(&response[..20]);
    Ok(hmac)
}
