#if !defined(POOL_ZERO_DOWN_LEVEL_SUPPORT)
#error POOL_ZERO_DOWN_LEVEL_SUPPORT is undefined
#endif
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <ntintsafe.h>
#ifndef Add2Ptr
#define Add2Ptr(P,I) ((PVOID)((PUCHAR)(P) + (I)))
#endif

#define KD_INFO(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
               DPFLTR_ERROR_LEVEL, \
               "[+] %s: " Format "\n", \
               __FUNCTION__, \
               __VA_ARGS__)

#define KD_ERROR(Format, ...) \
    DbgPrintEx(DPFLTR_IHVDRIVER_ID, \
               DPFLTR_ERROR_LEVEL, \
               "[-] %s: " Format "\n", \
               __FUNCTION__, \
               __VA_ARGS__)

#define KD_TAG00    ((ULONG)'00DK')

//
// Everything is pagable. Be a good memory citizen.
//
#pragma code_seg("PAGE")

//
// Windows' HalEfiRuntimeServicesBlock
//
typedef struct _HAL_RUNTIME_SERVICES_BLOCK
{
    void* GetTime;
    void* SetTime;
    void* ResetSystem;
    void* GetVariable;
    void* GetNextVariableName;
    void* SetVariable;
    void* UpdateCapsule;
    void* QueryCapsuleCapabilities;
    void* QueryVariableInfo;
} HAL_RUNTIME_SERVICES_BLOCK;
#define HAL_RUNTIME_SERVICES_COUNT  (sizeof(HAL_RUNTIME_SERVICES_BLOCK) / sizeof(void*))

static const char* k_RuntimeServiceNames[] =
{
    "GetTime",
    "SetTime",
    "ResetSystem",
    "GetVariable",
    "GetNextVariableName",
    "SetVariable",
    "UpdateCapsule",
    "QueryCapsuleCapabilities",
    "QueryVariableInfo",
};

//
// Information class 48 was originally published with this name, then removed.
//
#define HalQueryRuntimeServicesBlockInformation HalQueryUnused0001
typedef struct _HAL_RUNTIME_SERVICES_BLOCK_INFORMATION
{
    HAL_RUNTIME_SERVICES_BLOCK* ServicesBlock;
    SIZE_T BlockSizeInBytes;
} HAL_RUNTIME_SERVICES_BLOCK_INFORMATION;

/**
 * @brief Finds the address of HalEfiRuntimeServicesBlock using HalQuerySystemInformation
 * @param RuntimeServicesBlock
 * @return STATUS_SUCCESS on success.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FindHalEfiRuntimeServicesBlockByApi (
    _Outptr_ HAL_RUNTIME_SERVICES_BLOCK** RuntimeServicesBlock
    )
{
    NTSTATUS status;
    ULONG sizeWritten;
    HAL_RUNTIME_SERVICES_BLOCK_INFORMATION information;

    PAGED_CODE();

    //
    // Attempt to call HalpQueryRuntimeServicesBlockInformation. This may fail
    // on newer systems, with STATUS_INVALID_LEVEL for example.
    //
    status = HalQuerySystemInformation(HalQueryRuntimeServicesBlockInformation,
                                       sizeof(information),
                                       &information,
                                       &sizeWritten);
    if (!NT_SUCCESS(status))
    {
        if (status != STATUS_INVALID_LEVEL)
        {
            KD_ERROR("HalQuerySystemInformation failed : %08x", status);
        }
        goto Exit;
    }

    if (information.BlockSizeInBytes != sizeof(HAL_RUNTIME_SERVICES_BLOCK))
    {
        KD_ERROR("HalQuerySystemInformation returned an unexpected size: %llu",
                 information.BlockSizeInBytes);
        status = STATUS_UNKNOWN_REVISION;
        goto Exit;
    }

    *RuntimeServicesBlock = information.ServicesBlock;

Exit:
    return status;
}

/**
 * @brief Checks whether the physical address is known to the kernel.
 * @param MemoryRanges
 * @param PhysicalAddress
 * @return TRUE if the address is known to the kernel, or FALSE.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
BOOLEAN
IsKernelAwarePhysicalMemoryAddress (
    _In_ const PHYSICAL_MEMORY_RANGE* MemoryRanges,
    _In_ ULONG64 PhysicalAddress
    )
{
    PAGED_CODE();

    for (ULONG64 i = 0; /**/; ++i)
    {
        const PHYSICAL_MEMORY_RANGE* currentRange;
        ULONG64 baseAddress;
        ULONG64 endAddress;

        currentRange = &MemoryRanges[i];
        if ((currentRange->BaseAddress.QuadPart == 0) &&
            (currentRange->NumberOfBytes.QuadPart == 0))
        {
            return FALSE;
        }

        baseAddress = currentRange->BaseAddress.QuadPart;
        endAddress = currentRange->BaseAddress.QuadPart + currentRange->NumberOfBytes.QuadPart;
        if ((baseAddress <= PhysicalAddress) && (PhysicalAddress < endAddress))
        {
            return TRUE;
        }
    }
}

EXTERN_C
NTKERNELAPI
PVOID
NTAPI
RtlPcToFileHeader (
    _In_ PVOID PcValue,
    _Out_ PVOID* BaseOfImage
    );

/**
 * @brief Finds the address of HalEfiRuntimeServicesBlock with heuristic.
 * @param RuntimeServicesBlock
 * @return STATUS_SUCCESS on success.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FindHalEfiRuntimeServicesBlockByDirty (
    _Outptr_ HAL_RUNTIME_SERVICES_BLOCK** RuntimeServicesBlock
    )
{
    NTSTATUS status;
    PHYSICAL_MEMORY_RANGE* memoryRanges;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt;
    const IMAGE_SECTION_HEADER* sections;
    const void** cfgroSection;

    PAGED_CODE();

    *RuntimeServicesBlock = NULL;
    memoryRanges = NULL;
    cfgroSection = NULL;

    //
    // This function works by searching the contents of the CFGRO section in the
    // ntoskrnl.exe, where (so far) stores the pointer to HalEfiRuntimeServicesBlock
    // at its beginning (offset +0x10).
    //
    // First locate the section.
    //
    if (RtlPcToFileHeader((void*)ZwClose, (void*)&dos) == NULL)
    {
        KD_ERROR("RtlPcToFileHeader failed");
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KD_ERROR("No DOS signature found");
        status = STATUS_INVALID_IMAGE_NOT_MZ;
        goto Exit;
    }

    nt = (const IMAGE_NT_HEADERS64*)Add2Ptr(dos, dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        KD_ERROR("No NT signature found");
        status = STATUS_INVALID_SIGNATURE;
        goto Exit;
    }

    sections = (const IMAGE_SECTION_HEADER*)Add2Ptr(nt, sizeof(*nt));
    for (ULONG64 i = 0; i < nt->FileHeader.NumberOfSections; ++i)
    {
        if (RtlEqualMemory(sections[i].Name, "CFGRO\0\0", IMAGE_SIZEOF_SHORT_NAME) != FALSE)
        {
            cfgroSection = Add2Ptr(dos, sections[i].VirtualAddress);
            break;
        }
    }
    if (cfgroSection == NULL)
    {
        KD_ERROR("No CFGRO section found");
        status = STATUS_NOT_FOUND;
        goto Exit;
    }

    //
    // Now, we need to check contents to find HalEfiRuntimeServicesBlock. We do
    // this by checking contents of would-be HalEfiRuntimeServicesBlock. One of
    // check is to make sure the backing physical address is outside what the
    // kernel manages. To do this, get the list of kernel-managed physical address
    // ranges.
    //
    memoryRanges = MmGetPhysicalMemoryRanges();
    if (memoryRanges == NULL)
    {
        KD_ERROR("MmGetPhysicalMemoryRanges failed");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto Exit;
    }

    //
    // Go over at most 80 bytes (10 pointers) from the beginning of the section.
    //
    status = STATUS_NOT_FOUND;
    for (ULONG64 i = 0; i < 10; ++i)
    {
        NTSTATUS status2;
        void* imageBase;
        MM_COPY_ADDRESS sourceAddress;
        SIZE_T numberOfBytesTransferred;
        HAL_RUNTIME_SERVICES_BLOCK maybe = {0}; // C6001; annotation of MmCopyMemory is wrong

        //
        // Is it the pointer that points to inside ntoskrnl.exe?
        //
        if ((cfgroSection[i] == NULL) ||
            (RtlPcToFileHeader((void*)cfgroSection[i], &imageBase) != dos))
        {
            continue;
        }

        //
        // If so, attempt to capture the contents of the address. This may be
        // HalEfiRuntimeServicesBlock.
        //
        sourceAddress.VirtualAddress = (void*)cfgroSection[i];
        status2 = MmCopyMemory(&maybe,
                               sourceAddress,
                               sizeof(maybe),
                               MM_COPY_MEMORY_VIRTUAL,
                               &numberOfBytesTransferred);
        if (!NT_SUCCESS(status2))
        {
            continue;
        }

        //
        // Contents should be the pointers to somewhere kernel space if they are
        // runtime services. Note that no all services have contents, and those
        // checked to services may be NULL too (although the author did not see
        // the case).
        //
        if ((maybe.GetTime < MM_SYSTEM_RANGE_START) ||
            (maybe.QueryVariableInfo < MM_SYSTEM_RANGE_START))
        {
            continue;
        }

        //
        // Make sure those are backed by the physical memory outside what the
        // kernel manages.
        //
        if (IsKernelAwarePhysicalMemoryAddress(memoryRanges,
                                               MmGetPhysicalAddress(maybe.GetTime).QuadPart) ||
            IsKernelAwarePhysicalMemoryAddress(memoryRanges,
                                               MmGetPhysicalAddress(maybe.QueryVariableInfo).QuadPart))
        {
            continue;
        }

        *RuntimeServicesBlock = (HAL_RUNTIME_SERVICES_BLOCK*)cfgroSection[i];
        status = STATUS_SUCCESS;
        break;
    }

Exit:
    if (memoryRanges != NULL)
    {
        ExFreePoolWithTag(memoryRanges, 'hPmM');
    }
    return status;
}

/**
 * @brief Finds the address of HalEfiRuntimeServicesBlock.
 * @param RuntimeServicesBlock
 * @return STATUS_SUCCESS on success.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
FindHalEfiRuntimeServicesBlock (
    _Outptr_ HAL_RUNTIME_SERVICES_BLOCK** RuntimeServicesBlock
    )
{
    NTSTATUS status;

    PAGED_CODE();

    status = FindHalEfiRuntimeServicesBlockByApi(RuntimeServicesBlock);
    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_UNKNOWN_REVISION)
        {
            goto Exit;
        }

        status = FindHalEfiRuntimeServicesBlockByDirty(RuntimeServicesBlock);
        if (!NT_SUCCESS(status))
        {
            KD_ERROR("FindHalEfiRuntimeServicesBlockByDirty failed : %08x", status);
            goto Exit;
        }
    }

Exit:
    return status;
}

/**
 * @brief Finds the base address of the image where the specified address belongs to.
 * @param TargetAddress
 * @return The image base address if found, or NULL.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
void*
FindImageBase (
    _In_ const void* TargetAddress
    )
{
    void* imageBase;

    PAGED_CODE();

    //
    // Search the DOS header up to 0x10000 bytes (16 pages). This is arbitrary.
    //
    imageBase = PAGE_ALIGN(TargetAddress);
    for (ULONG64 i = 0; i < 16; i++, imageBase = Add2Ptr(imageBase, -PAGE_SIZE))
    {
        const IMAGE_DOS_HEADER* dos;

        //
        // Exit if we encounter the page that is not backed by a physical address.
        // All runtime drivers are physical memory resident and encountering this
        // mean we went outside of the image.
        //
        if (MmGetPhysicalAddress(imageBase).QuadPart == 0)
        {
            break;
        }

        dos = imageBase;
        if (dos->e_magic == IMAGE_DOS_SIGNATURE)
        {
            goto Exit;
        }
    }

    imageBase = NULL;

Exit:
    return imageBase;
}

typedef struct _ADDRESS_INFORMATION
{
    void* Function;
    void* ImageBase;
} ADDRESS_INFORMATION;

/**
 * @brief Finds the base addresses of the images which implement runtime services.
 * @param ServicesBlock
 * @param AddressInformation
 * @param AddressInformationCount
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
void
FindRuntimeDrivers (
    _In_ const HAL_RUNTIME_SERVICES_BLOCK* ServicesBlock,
    _Out_writes_bytes_(AddressInformationCount * sizeof(ADDRESS_INFORMATION))
        ADDRESS_INFORMATION* AddressInformation,
    _In_ SIZE_T AddressInformationCount
    )
{
    PAGED_CODE();

    NT_ASSERT(AddressInformationCount >= HAL_RUNTIME_SERVICES_COUNT);

    RtlZeroMemory(AddressInformation, AddressInformationCount * sizeof(ADDRESS_INFORMATION));

    for (ULONG64 i = 0; i < HAL_RUNTIME_SERVICES_COUNT; ++i)
    {
        AddressInformation[i].Function = ((void**)ServicesBlock)[i];
        AddressInformation[i].ImageBase = FindImageBase(AddressInformation[i].Function);
        if (AddressInformation[i].ImageBase != NULL)
        {
            KD_INFO("%-24s at %p belongs to %p",
                    k_RuntimeServiceNames[i],
                    AddressInformation[i].Function,
                    AddressInformation[i].ImageBase);
        }
        else
        {
            KD_INFO("%-24s at %p does not belong to an image",
                    k_RuntimeServiceNames[i],
                    AddressInformation[i].Function);
        }
    }
}

/**
 * @brief Writes a file of the memory range, assuming those addresses are all
 *      memory resident and safe to access. This would be true with runtime drivers.
 * @details Note that MmCopyMemory cannot be used to capture the contents of
 *      the runtime driver, regardless of whether virtual or physical address is
 *      specified. This API does not allow you to access outside of where the
 *      kernel manages.
 * @param BaseAddress
 * @param PageCount
 * @return STATUS_SUCCESS on success.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DumpPages (
    _In_ const void* BaseAddress,
    _In_ ULONG PageCount
    )
{
    NTSTATUS status;
    UNICODE_STRING filePath;
    OBJECT_ATTRIBUTES objectAttributes;
    IO_STATUS_BLOCK ioStatusBlock;
    WCHAR filePathBuffer[33];
    HANDLE fileHandle;
    ULONG byteToRead;

    PAGED_CODE();

    NT_ASSERT(PAGE_ALIGN(BaseAddress) == BaseAddress);
    NT_ASSERT(PageCount != 0);

    fileHandle = NULL;

    //
    // Test that all requested memory ranges are backed by physical memory, which
    // should be the case with runtime drivers.
    //
    for (ULONG64 i = 0; i < PageCount; ++i)
    {
        if (MmGetPhysicalAddress(Add2Ptr(BaseAddress, i * PAGE_SIZE)).QuadPart == 0)
        {
            KD_ERROR("Address %p is not backed by physical memory",
                     Add2Ptr(BaseAddress, i * PAGE_SIZE));
            status = STATUS_ADDRESS_NOT_ASSOCIATED;
            goto Exit;
        }
    }

    //
    // Save the file as C:\Windows\<address_in_hex>.bin
    //
    status = RtlStringCchPrintfW(filePathBuffer,
                                 RTL_NUMBER_OF(filePathBuffer),
                                 L"\\SystemRoot\\%016llx.bin",
                                 (ULONG64)BaseAddress);
    if (!NT_VERIFY(NT_SUCCESS(status)))
    {
        KD_ERROR("RtlStringCchPrintfW failed : %08x", status);
        goto Exit;
    }

    RtlInitUnicodeString(&filePath, filePathBuffer);
    InitializeObjectAttributes(&objectAttributes,
                               &filePath,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL,
                               NULL);
    status = ZwCreateFile(&fileHandle,
                          GENERIC_WRITE,
                          &objectAttributes,
                          &ioStatusBlock,
                          NULL,
                          FILE_ATTRIBUTE_NORMAL,
                          FILE_SHARE_READ,
                          FILE_CREATE,
                          FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE,
                          NULL,
                          0);
    if (!NT_SUCCESS(status))
    {
        //
        // Do not overwrite if there is already the same file. (maybe better to
        // do so. Up to you.)
        //
        if (status != STATUS_OBJECT_NAME_COLLISION)
        {
            KD_ERROR("ZwCreateFile failed : %08x", status);
        }
        goto Exit;
    }

    status = RtlULongMult(PageCount, PAGE_SIZE, &byteToRead);
    if (!NT_SUCCESS(status))
    {
        KD_ERROR("RtlULongMult failed : %08x", status);
        goto Exit;
    }

    status = ZwWriteFile(fileHandle,
                         NULL,
                         NULL,
                         NULL,
                         &ioStatusBlock,
                         (void*)BaseAddress,
                         byteToRead,
                         NULL,
                         NULL);
    if (!NT_SUCCESS(status))
    {
        KD_ERROR("ZwWriteFile failed : %08x", status);
        goto Exit;
    }

Exit:
    if (fileHandle != NULL)
    {
        NT_VERIFY(NT_SUCCESS(ZwClose(fileHandle)));
    }
    return status;
}

/**
 * @brief Locates the range of the runtime driver in memory and writes it to a file.
 * @param ImageBase
 * @param Function
 * @return STATUS_SUCCESS on success.
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
_Must_inspect_result_
NTSTATUS
DumpDriver (
    _In_ const void* ImageBase,
    _In_ const void* Function
    )
{
    NTSTATUS status;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nt;
    ULONG imagePageCount;

    PAGED_CODE();

    NT_ASSERT(PAGE_ALIGN(ImageBase) == ImageBase);

    //
    // Get the SizeOfImage field from the PE header.
    //
    dos = (IMAGE_DOS_HEADER*)ImageBase;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        KD_ERROR("Image base did not have the DOS signature");
        status = STATUS_INVALID_SIGNATURE;
        goto Exit;
    }

    nt = (IMAGE_NT_HEADERS64*)Add2Ptr(ImageBase, dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
    {
        KD_ERROR("Image base did not have the NT signature");
        status = STATUS_INVALID_SIGNATURE;
        goto Exit;
    }

    imagePageCount = BYTES_TO_PAGES(nt->OptionalHeader.SizeOfImage);

    //
    // If the size indicated by the header does not include the address of the
    // runtime service, adjust it so that at least up to the address is included.
    //
    if ((ULONG64)Add2Ptr(ImageBase, (ULONG64)imagePageCount * PAGE_SIZE) < (ULONG64)Function)
    {
        imagePageCount = (ULONG)BYTES_TO_PAGES((ULONG64)Function - (ULONG64)ImageBase);
        imagePageCount = (imagePageCount == 0) ? 1 : imagePageCount;
        KD_INFO("Image did not have a valid SizeOfImage. Dumping %lu pages", imagePageCount);
    }

    //
    // Write the located memory range to a file.
    //
    status = DumpPages(ImageBase, imagePageCount);
    if (!NT_SUCCESS(status))
    {
        if (status == STATUS_OBJECT_NAME_COLLISION)
        {
            status = STATUS_SUCCESS;
            goto Exit;
        }

        KD_ERROR("DumpPages failed : %08x", status);
        goto Exit;
    }

    KD_INFO("Dumped %p - %p (%lu pages)",
            ImageBase,
            Add2Ptr(ImageBase, (ULONG64)imagePageCount * PAGE_SIZE),
            imagePageCount);

Exit:
    return status;
}

/**
 * @brief Writes located runtime services/driver images to files.
 * @param AddressInformation
 * @param AddressInformationCount
*/
static
_IRQL_requires_(PASSIVE_LEVEL)
void
DumpRuntimeDrivers (
    _In_reads_bytes_(AddressInformationCount * sizeof(ADDRESS_INFORMATION))
        const ADDRESS_INFORMATION* AddressInformation,
    _In_ SIZE_T AddressInformationCount
    )
{
    PAGED_CODE();

    NT_ASSERT(AddressInformationCount != 0);

    for (ULONG64 i = 0; i < AddressInformationCount; ++i)
    {
        NTSTATUS status;

        //
        // If the image base is located, try writing the whole image range. If
        // this fails, fail back to writing a single page where the runtime
        // service routine belongs to.
        //
        if (AddressInformation[i].ImageBase != NULL)
        {
            status = DumpDriver(AddressInformation[i].ImageBase,
                                AddressInformation[i].Function);
            if (NT_SUCCESS(status))
            {
                continue;
            }
        }

        //
        // Write only a page where the runtime service routine belongs to.
        //
        status = DumpPages(PAGE_ALIGN(AddressInformation[i].Function), 1);
        if (!NT_SUCCESS(status))
        {
            if (status != STATUS_OBJECT_NAME_COLLISION)
            {
                KD_ERROR("DumpPages failed : %08x", status);
            }
            continue;
        }
        KD_INFO("Dumped %p - %p",
                PAGE_ALIGN(AddressInformation[i].Function),
                Add2Ptr(PAGE_ALIGN(AddressInformation[i].Function), PAGE_SIZE));
    }
}

/**
 * @brief The entry point of this module.
 * @param DriverObject
 * @param RegistryPath
 * @return STATUS_CANCELLED on success.
*/
_Function_class_(DRIVER_INITIALIZE)
_IRQL_requires_same_
_IRQL_requires_(PASSIVE_LEVEL)
NTSTATUS
DriverEntry (
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS status;
    RTL_OSVERSIONINFOW version;
    HAL_RUNTIME_SERVICES_BLOCK* runtimeServicesBlock;
    ADDRESS_INFORMATION addressInfo[HAL_RUNTIME_SERVICES_COUNT];

    PAGED_CODE();

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    KdBreakPoint();

    //
    // Enable zeroed pool allocation
    //
    ExInitializeDriverRuntime(0);

    //
    // Windows 10 (or later) only is supported.
    //
    version.dwOSVersionInfoSize = sizeof(version);
    status = RtlGetVersion(&version);
    if (!NT_SUCCESS(status))
    {
        KD_ERROR("RtlGetVersion failed : %08x", status);
        goto Exit;
    }

    if (version.dwMajorVersion < 10)
    {
        KD_ERROR("Unsupported OS version. Only Windows 10 / Server 2019 or later is supported");
        status = STATUS_NOT_SUPPORTED;
        goto Exit;
    }

    //
    // Get the address of the hal! / nt!HalEfiRuntimeServicesBlock
    //
    status = FindHalEfiRuntimeServicesBlock(&runtimeServicesBlock);
    if (!NT_SUCCESS(status))
    {
        KD_ERROR("FindHalEfiRuntimeServicesBlock failed : %08x", status);
        goto Exit;
    }
    KD_INFO("HalEfiRuntimeServicesBlock found at %p", runtimeServicesBlock);

    //
    // Attempt to locate the base addresses of images implementing those runtime
    // services, then dump associated pages to files.
    //
    FindRuntimeDrivers(runtimeServicesBlock, addressInfo, RTL_NUMBER_OF(addressInfo));
    DumpRuntimeDrivers(addressInfo, RTL_NUMBER_OF(addressInfo));
    KD_INFO("Successfully processed runtime services/drivers");

    //
    // All done. Forcibly unload this driver by returning an error code.
    //
    status = STATUS_CANCELLED;

Exit:
    return status;
}
