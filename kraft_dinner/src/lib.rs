#![no_std]
#![allow(non_snake_case)]
#![allow(non_camel_case_types)]

use core::panic::PanicInfo;
use ntapi::{ntdbg::*, ntioapi::*, ntrtl::*, ntzwapi::*, winapi::shared::ntdef::*};
use utf16_lit::utf16_null;
use winapi::um::winnt::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER,
};

pub mod log;

// Looks like core:: needs this.
// See: https://github.com/Trantect/win_driver_example/issues/4
#[export_name = "_fltused"]
static _FLTUSED: i32 = 0;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    unsafe {
        DbgBreakPoint();
    }
    loop {}
}

// NT related definitions.
#[allow(overflowing_literals)]
const STATUS_CANCELLED: NTSTATUS = 0xC0000120;
const PAGE_SIZE: u32 = 0x1000;

extern "system" {
    pub fn RtlPcToFileHeader(PcValue: PVOID, BaseOfImage: *mut PVOID) -> PVOID;
    pub fn MmCopyMemory(
        TargetAddress: PVOID, SourceAddress: u64, NumberOfBytes: usize, Flags: u32,
        NumberOfBytesTransferred: *mut usize,
    ) -> NTSTATUS;
    pub fn MmGetPhysicalAddress(BaseAddress: PVOID) -> u64;
}

extern "cdecl" {
    pub fn _snwprintf(Dest: PWSTR, Count: usize, Format: PCWSTR, ...) -> i32;
}

// Rust DriverEntry
#[no_mangle]
pub extern "system" fn driver_entry() -> NTSTATUS {
    // Break into a debugger with a debug build.
    if cfg!(debug_assertions) {
        unsafe { DbgBreakPoint() };
    }

    let block = HalEfiRuntimeServicesBlock::find();
    if !block.is_some() {
        return STATUS_CANCELLED;
    }

    let address = block.unwrap().address;
    log!("HalEfiRuntimeServicesBlock found at %p", address);
    let mut name_index = 0;
    for service in unsafe { core::slice::from_raw_parts(address as *mut u64, 9) } {
        dump_runtime_driver(*service, SERVICE_NAMES[name_index]);
        name_index += 1;
    }

    log!("Successfully processed runtime services/drivers");
    STATUS_CANCELLED
}

const SERVICE_NAMES: [&str; 9] = [
    "GetTime\0",
    "SetTime\0",
    "ResetSystem\0",
    "GetVariable\0",
    "GetNextVariableName\0",
    "SetVariable\0",
    "UpdateCapsule\0",
    "QueryCapsuleCapabilities\0",
    "QueryVariableInfo\0",
];

fn dump_runtime_driver(service_address: u64, service_name: &str) {
    let mut image_base = service_address & (!0xfff);
    for _i in 0..16 {
        image_base -= PAGE_SIZE as u64;
        if unsafe { MmGetPhysicalAddress(image_base as PVOID) } == 0 {
            continue;
        }

        let dos = unsafe { &*(image_base as *const IMAGE_DOS_HEADER) };
        if dos.e_magic != IMAGE_DOS_SIGNATURE {
            continue;
        }

        log!(
            "%-24s at %p belongs to %p",
            service_name.as_ptr(),
            service_address,
            image_base
        );

        let nt = unsafe {
            &*((image_base as u64 + (*dos).e_lfanew as u64) as *const IMAGE_NT_HEADERS64)
        };
        let size_of_image = nt.OptionalHeader.SizeOfImage;
        if size_of_image == 0 {
            break;
        }

        let page_count = if size_of_image % PAGE_SIZE == 0 {
            size_of_image / PAGE_SIZE
        } else {
            (size_of_image / PAGE_SIZE) + 1
        };

        dump_pages(image_base, page_count);
        break;
    }
}

fn dump_pages(base_address: u64, page_count: u32) {
    for i in 0..page_count {
        let page_to_test = base_address + (i * PAGE_SIZE) as u64;
        if unsafe { MmGetPhysicalAddress(page_to_test as PVOID) } == 0 {
            return;
        }
    }

    const FORMAT_STRING: &[u16] = utf16_null!("\\SystemRoot\\%016llx.bin");
    let mut buffer: [WCHAR; 33] = [0; 33];
    if unsafe { _snwprintf(&mut buffer[0], 33, &FORMAT_STRING[0], base_address) } == -1 {
        return;
    }

    let mut file_path = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut file_path, &mut buffer[0]) };
    let mut oa = OBJECT_ATTRIBUTES::default();
    unsafe {
        InitializeObjectAttributes(
            &mut oa,
            &mut file_path,
            OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
            NULL,
            NULL,
        )
    };
    let mut io_status = IO_STATUS_BLOCK::default();
    let mut file_handle: HANDLE = core::ptr::null_mut();
    let mut status = unsafe {
        ZwCreateFile(
            &mut file_handle,
            0x40000000, //GENERIC_WRITE
            &mut oa,
            &mut io_status,
            NULL as PLARGE_INTEGER,
            0x80, //FILE_ATTRIBUTE_NORMAL,
            0x1,  //FILE_SHARE_READ
            0x2,  //FILE_CREATE
            0x60, //FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE
            NULL,
            0,
        )
    };
    if !NT_SUCCESS(status) {
        return;
    }
    status = unsafe {
        ZwWriteFile(
            file_handle,
            NULL,
            None,
            NULL,
            &mut io_status,
            base_address as PVOID,
            page_count * PAGE_SIZE,
            NULL as PLARGE_INTEGER,
            NULL as PULONG,
        )
    };
    unsafe { ZwClose(file_handle) };
    if !NT_SUCCESS(status) {
        return;
    }
    log!(
        "Dumped %llX - %llX (%lu pages)",
        base_address,
        base_address + (page_count * PAGE_SIZE) as u64,
        page_count,
    );
}

// More HalEfiRuntimeServicesBlock related definitions.
#[repr(C)]
pub enum HAL_SET_INFORMATION_CLASS {
    HalQueryRuntimeServicesBlockInformation = 48,
}

pub type pHalQuerySystemInformation = extern "system" fn(
    InformationClass: HAL_SET_INFORMATION_CLASS,
    BufferSize: ULONG,
    Buffer: PVOID,
    ReturnedLength: PULONG,
) -> NTSTATUS;

#[repr(C)]
pub struct HAL_DISPATCH {
    pub Version: u32,
    pub HalQuerySystemInformation: pHalQuerySystemInformation,
}

extern "system" {
    static HalDispatchTable: *mut HAL_DISPATCH;
    static MmSystemRangeStart: u64;
}

#[repr(C)]
pub struct HAL_RUNTIME_SERVICES_BLOCK_INFORMATION {
    pub ServicesBlock: PVOID,
    pub BlockSizeInBytes: usize,
}
impl Default for HAL_RUNTIME_SERVICES_BLOCK_INFORMATION {
    fn default() -> HAL_RUNTIME_SERVICES_BLOCK_INFORMATION {
        HAL_RUNTIME_SERVICES_BLOCK_INFORMATION {
            ServicesBlock: core::ptr::null_mut(),
            BlockSizeInBytes: 0,
        }
    }
}

#[derive(Default)]
#[repr(C)]
pub struct HAL_RUNTIME_SERVICES_BLOCK {
    pub GetTime: u64,
    pub SetTime: u64,
    pub ResetSystem: u64,
    pub GetVariable: u64,
    pub GetNextVariableName: u64,
    pub SetVariable: u64,
    pub UpdateCapsule: u64,
    pub QueryCapsuleCapabilities: u64,
    pub QueryVariableInfo: u64,
}

pub struct HalEfiRuntimeServicesBlock {
    pub address: *mut HAL_RUNTIME_SERVICES_BLOCK,
}
impl HalEfiRuntimeServicesBlock {
    pub fn find() -> Option<Self> {
        // Try HalQuerySystemInformation first.
        unsafe {
            assert!(!HalDispatchTable.is_null());
        }
        let dispatch_table = unsafe { &mut *HalDispatchTable };

        let mut size: u32 = 0;
        let mut information = HAL_RUNTIME_SERVICES_BLOCK_INFORMATION::default();
        let status = (dispatch_table.HalQuerySystemInformation)(
            HAL_SET_INFORMATION_CLASS::HalQueryRuntimeServicesBlockInformation,
            core::mem::size_of::<HAL_RUNTIME_SERVICES_BLOCK_INFORMATION>() as ULONG,
            &mut information as *mut HAL_RUNTIME_SERVICES_BLOCK_INFORMATION as PVOID,
            &mut size,
        );
        if NT_SUCCESS(status) {
            // If the API succeeds and the reported structure size is unexpected,
            // bail out. We do not know how to handle this version of struct.
            if information.BlockSizeInBytes != core::mem::size_of::<HAL_RUNTIME_SERVICES_BLOCK>() {
                return None;
            }
            return Some(Self {
                address: information.ServicesBlock as *mut HAL_RUNTIME_SERVICES_BLOCK,
            });
        }

        // Could not get the pointer with the API. Do the dirty job.
        Self::find_by_heuristic()
    }

    fn find_by_heuristic() -> Option<Self> {
        // Get the CFGRO section in ntoskrnl.exe
        let mut nt_base: PVOID = core::ptr::null_mut();
        let zw_close_addr = ZwClose as PVOID;
        unsafe {
            if RtlPcToFileHeader(zw_close_addr, &mut nt_base).is_null() {
                return None;
            }
        };
        let dos = nt_base as *const IMAGE_DOS_HEADER;
        if unsafe { (*dos).e_magic } != IMAGE_DOS_SIGNATURE {
            return None;
        }
        let nt = unsafe { nt_base as u64 + (*dos).e_lfanew as u64 } as *const IMAGE_NT_HEADERS64;
        let mut cfgroSection = 0;
        let sections = unsafe {
            core::slice::from_raw_parts(
                (nt as u64 + core::mem::size_of::<IMAGE_NT_HEADERS64>() as u64)
                    as *const IMAGE_SECTION_HEADER,
                (*nt).FileHeader.NumberOfSections as usize,
            )
        };
        for section in sections {
            if section.Name == [0x43, 0x46, 0x47, 0x52, 0x4F, 0, 0, 0] {
                cfgroSection = nt_base as u64 + section.VirtualAddress as u64;
            }
        }
        if cfgroSection == 0 {
            return None;
        }

        // Found the CFGRO section. Check that contents.
        let contents = unsafe { core::slice::from_raw_parts(cfgroSection as *mut u64, 10) };
        for value64 in contents {
            let mut image_base: PVOID = core::ptr::null_mut();
            if *value64 == 0
                || unsafe { RtlPcToFileHeader(*value64 as PVOID, &mut image_base) } != nt_base
            {
                continue;
            }

            let mut bytes_read: usize = 0;
            let mut maybe = HAL_RUNTIME_SERVICES_BLOCK::default();
            let status = unsafe {
                MmCopyMemory(
                    &mut maybe as *mut _ as PVOID,
                    *value64,
                    core::mem::size_of::<HAL_RUNTIME_SERVICES_BLOCK>(),
                    2, // MM_COPY_MEMORY_VIRTUAL
                    &mut bytes_read,
                )
            };
            if !NT_SUCCESS(status) {
                continue;
            }

            unsafe {
                if maybe.GetTime < MmSystemRangeStart
                    || maybe.QueryVariableInfo < MmSystemRangeStart
                {
                    continue;
                }
            }

            // I am being laze and going to skip further checks. See the C version.
            return Some(Self {
                address: *value64 as *mut HAL_RUNTIME_SERVICES_BLOCK,
            });
        }
        None
    }
}
