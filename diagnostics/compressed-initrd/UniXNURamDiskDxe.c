/** @file
  Publish the FAT initrd from a Mu-Silicium FDT handoff as a read-only block device.

  SPDX-License-Identifier: BSD-2-Clause
**/

#include <Uefi.h>
#include <Library/BaseCryptLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/FdtLib.h>
#include <Library/HobLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>

// Mu-Silicium SEC stores the incoming x0 value in this HOB as a UINT64.
STATIC CONST EFI_GUID mEntryArgHobGuid = {
  0xDAEE82E6, 0x8090, 0x4E72, { 0xBF, 0xB9, 0x78, 0xC1, 0x3C, 0xD4, 0xE3, 0x59 }
};

STATIC
UINT64
ReadCells (
  IN CONST VOID  *Data,
  IN UINT32      Cells
  )
{
  if (Cells == 2) {
    return Fdt64ToCpu (ReadUnaligned64 (Data));
  }

  return Fdt32ToCpu (ReadUnaligned32 (Data));
}

#define RAM_BLOCK_SIZE          512
#define RAM_MAX_RAW_BYTES       (256ULL * 1024 * 1024)
#define RAM_MAX_ENCODED_BYTES   (96ULL * 1024 * 1024)
#define RAM_ENVELOPE_SIZE       56
#define RAM_LZMA_HEADER_SIZE    13
#define RAM_MAX_SCRATCH_BYTES   (1024 * 1024)

//
// MdeModulePkg/Library/LzmaCustomDecompressLib is a NULL library instance,
// not a named LzmaDecompressLib class. Upstream has no public library header;
// these signatures match its LzmaDecompressLibInternal.h (EDK II master).
// Link that NULL instance in this module's DSC <LibraryClasses> overrides.
//
RETURN_STATUS
EFIAPI
LzmaUefiDecompressGetInfo (
  IN  CONST VOID  *Source,
  IN  UINT32      SourceSize,
  OUT UINT32      *DestinationSize,
  OUT UINT32      *ScratchSize
  );

RETURN_STATUS
EFIAPI
LzmaUefiDecompress (
  IN CONST VOID  *Source,
  IN UINTN       SourceSize,
  IN OUT VOID    *Destination,
  IN OUT VOID    *Scratch
  );

STATIC CONST UINT8  mCompressedMagic[8] = { 'U', 'N', 'X', 'N', 'L', 'Z', '0', '1' };

STATIC
UINT64
ReadLittleEndian64 (
  IN CONST UINT8  *Data
  )
{
  UINT64  Value;
  UINTN   Index;

  Value = 0;
  for (Index = 0; Index < sizeof (Value); Index++) {
    Value |= LShiftU64 ((UINT64)Data[Index], (UINTN)(Index * 8));
  }

  return Value;
}

//
// UNXNLZ01 wire format (no native structure layout): magic[8], raw bytes LE64,
// compressed bytes LE64, SHA256(raw)[32], then one LZMA-alone stream, including
// its 13-byte header. Compressed length excludes this 56-byte envelope. Require
// exact length; container/partition padding must not be part of the FDT initrd.
// The hash detects corruption, not authenticity; the boot chain supplies trust.
//
STATIC
EFI_STATUS
ExpandInitrd (
  IN  CONST UINT8          *Source,
  IN  UINTN               SourceSize,
  OUT EFI_PHYSICAL_ADDRESS *Destination,
  OUT UINTN               *DestinationSize
  )
{
  EFI_STATUS            Status;
  RETURN_STATUS         DecodeStatus;
  UINT64                RawBytes;
  UINT64                EncodedBytes;
  CONST UINT8           *Encoded;
  UINT32                DecodedSize;
  UINT32                ScratchSize;
  EFI_PHYSICAL_ADDRESS  Scratch;
  UINT8                 Hash[SHA256_DIGEST_SIZE];

  *Destination = 0;
  *DestinationSize = 0;
  if (SourceSize < RAM_ENVELOPE_SIZE + RAM_LZMA_HEADER_SIZE) {
    return EFI_COMPROMISED_DATA;
  }

  RawBytes     = ReadLittleEndian64 (Source + 8);
  EncodedBytes = ReadLittleEndian64 (Source + 16);
  if ((RawBytes == 0) || (RawBytes > RAM_MAX_RAW_BYTES) ||
      ((RawBytes % RAM_BLOCK_SIZE) != 0) ||
      (EncodedBytes < RAM_LZMA_HEADER_SIZE) ||
      (EncodedBytes > RAM_MAX_ENCODED_BYTES) ||
      (SourceSize > RAM_MAX_ENCODED_BYTES) ||
      (EncodedBytes != SourceSize - RAM_ENVELOPE_SIZE))
  {
    return EFI_COMPROMISED_DATA;
  }

  Encoded = Source + RAM_ENVELOPE_SIZE;
  // Reject unknown-size streams before EDK II derives its destination capacity.
  // Fix lc/lp/pb to the usual 3/0/2 profile (0x5d), whose probability workspace
  // fits EDK II's fixed 64 KiB scratch allocator; arbitrary properties can ASSERT.
  if ((Encoded[0] != 0x5d) || (ReadLittleEndian64 (Encoded + 5) != RawBytes)) {
    return EFI_COMPROMISED_DATA;
  }

  DecodeStatus = LzmaUefiDecompressGetInfo (
                   Encoded, (UINT32)EncodedBytes, &DecodedSize, &ScratchSize);
  if (RETURN_ERROR (DecodeStatus) || (DecodedSize != RawBytes) ||
      (ScratchSize == 0) || (ScratchSize > RAM_MAX_SCRATCH_BYTES))
  {
    return EFI_COMPROMISED_DATA;
  }

  Status = gBS->AllocatePages (
                  AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES ((UINTN)RawBytes), Destination);
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Scratch = 0;
  Status = gBS->AllocatePages (
                  AllocateAnyPages, EfiLoaderData, EFI_SIZE_TO_PAGES (ScratchSize), &Scratch);
  if (!EFI_ERROR (Status)) {
    // EDK II does not report actual decoded/consumed lengths. Initialize all
    // output and require the full raw hash before publishing any bytes.
    ZeroMem ((VOID *)(UINTN)*Destination, (UINTN)RawBytes);
    DecodeStatus = LzmaUefiDecompress (
                     Encoded, (UINTN)EncodedBytes, (VOID *)(UINTN)*Destination, (VOID *)(UINTN)Scratch);
    gBS->FreePages (Scratch, EFI_SIZE_TO_PAGES (ScratchSize));
    if (RETURN_ERROR (DecodeStatus)) {
      Status = EFI_COMPROMISED_DATA;
    } else if (!Sha256HashAll ((VOID *)(UINTN)*Destination, (UINTN)RawBytes, Hash)) {
      Status = EFI_DEVICE_ERROR;
    } else if (CompareMem (Hash, Source + 24, sizeof (Hash)) != 0) {
      Status = EFI_CRC_ERROR;
    }
  }

  if (EFI_ERROR (Status)) {
    gBS->FreePages (*Destination, EFI_SIZE_TO_PAGES ((UINTN)RawBytes));
    *Destination = 0;
    return Status;
  }

  *DestinationSize = (UINTN)RawBytes;
  return EFI_SUCCESS;
}

#pragma pack(1)
typedef struct {
  VENDOR_DEVICE_PATH          Vendor;
  EFI_DEVICE_PATH_PROTOCOL    End;
} RAM_BLOCK_DEVICE_PATH;
#pragma pack()

STATIC RAM_BLOCK_DEVICE_PATH  mDevicePath = {
  {
    { HARDWARE_DEVICE_PATH, HW_VENDOR_DP, { (UINT8)sizeof (VENDOR_DEVICE_PATH), (UINT8)(sizeof (VENDOR_DEVICE_PATH) >> 8) } },
    { 0xA9C6827C, 0x1BD8, 0x410C, { 0x88, 0x5A, 0xC4, 0x65, 0x00, 0xF7, 0xD8, 0x36 } }
  },
  { END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 } }
};

STATIC UINT8                    *mRamBase;
STATIC EFI_BLOCK_IO_MEDIA       mMedia;
STATIC EFI_HANDLE               mRamHandle;

STATIC
EFI_STATUS
EFIAPI
RamBlockReset (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN BOOLEAN                ExtendedVerification
  )
{
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockRead (
  IN  EFI_BLOCK_IO_PROTOCOL  *This,
  IN  UINT32                 MediaId,
  IN  EFI_LBA                Lba,
  IN  UINTN                  BufferSize,
  OUT VOID                   *Buffer
  )
{
  if (Buffer == NULL) {
    return EFI_INVALID_PARAMETER;
  }

  if (MediaId != mMedia.MediaId) {
    return EFI_MEDIA_CHANGED;
  }

  if ((BufferSize % RAM_BLOCK_SIZE) != 0) {
    return EFI_BAD_BUFFER_SIZE;
  }

  if ((Lba > mMedia.LastBlock) || ((BufferSize / RAM_BLOCK_SIZE) > (mMedia.LastBlock + 1 - Lba))) {
    return EFI_INVALID_PARAMETER;
  }

  CopyMem (Buffer, mRamBase + Lba * RAM_BLOCK_SIZE, BufferSize);
  return EFI_SUCCESS;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockWrite (
  IN EFI_BLOCK_IO_PROTOCOL  *This,
  IN UINT32                 MediaId,
  IN EFI_LBA                Lba,
  IN UINTN                  BufferSize,
  IN VOID                   *Buffer
  )
{
  return EFI_WRITE_PROTECTED;
}

STATIC
EFI_STATUS
EFIAPI
RamBlockFlush (
  IN EFI_BLOCK_IO_PROTOCOL  *This
  )
{
  return EFI_SUCCESS;
}

STATIC EFI_BLOCK_IO_PROTOCOL  mBlockIo = {
  EFI_BLOCK_IO_PROTOCOL_REVISION,
  &mMedia,
  RamBlockReset,
  RamBlockRead,
  RamBlockWrite,
  RamBlockFlush
};

STATIC
VOID
PublishInitrd (
  IN CONST VOID  *Fdt
  )
{
  EFI_STATUS  Status;
  INT32       Chosen;
  CONST VOID  *StartProp;
  CONST VOID  *EndProp;
  INT32       StartLength;
  INT32       EndLength;
  UINT64      Start;
  UINT64      End;
  EFI_PHYSICAL_ADDRESS  AllocatedBase;
  UINTN                 AllocatedPages;
  UINTN                 Size;

  // Both raw and compressed paths publish through this single install site.
  if (mRamHandle != NULL) {
    return;
  }

  AllocatedBase  = 0;
  AllocatedPages = 0;
  Chosen = FdtPathOffset (Fdt, "/chosen");
  if (Chosen < 0) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no /chosen\n"));
    return;
  }

  StartProp = FdtGetProp (Fdt, Chosen, "linux,initrd-start", &StartLength);
  EndProp   = FdtGetProp (Fdt, Chosen, "linux,initrd-end", &EndLength);
  if ((StartProp == NULL) || (EndProp == NULL) ||
      ((StartLength != 4) && (StartLength != 8)) || ((EndLength != 4) && (EndLength != 8)))
  {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no initrd in /chosen\n"));
    return;
  }

  Start = ReadCells (StartProp, StartLength / 4);
  End   = ReadCells (EndProp, EndLength / 4);
  if ((Start == 0) || (End <= Start) || (Start > MAX_UINTN) || (End > MAX_UINTN) ||
      ((End - Start) > RAM_MAX_RAW_BYTES))
  {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: empty initrd 0x%lx-0x%lx\n", Start, End));
    return;
  }

  Size = (UINTN)(End - Start);
  if ((Size >= sizeof (mCompressedMagic)) &&
      (CompareMem ((VOID *)(UINTN)Start, mCompressedMagic, sizeof (mCompressedMagic)) == 0))
  {
    Status = ExpandInitrd ((CONST UINT8 *)(UINTN)Start, Size, &AllocatedBase, &Size);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: compressed initrd rejected: %r\n", Status));
      return;
    }

    AllocatedPages = EFI_SIZE_TO_PAGES (Size);
    mRamBase = (UINT8 *)(UINTN)AllocatedBase;
  } else if ((Size % RAM_BLOCK_SIZE) != 0) {
    // Preserve raw handoffs with a partial last sector, but never read beyond
    // the FDT range. Copy exactly Size bytes and zero-pad our owned allocation.
    AllocatedPages = EFI_SIZE_TO_PAGES (Size);
    Status = gBS->AllocatePages (AllocateAnyPages, EfiLoaderData, AllocatedPages, &AllocatedBase);
    if (EFI_ERROR (Status)) {
      DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: raw initrd allocation failed: %r\n", Status));
      return;
    }

    mRamBase = (UINT8 *)(UINTN)AllocatedBase;
    ZeroMem (mRamBase, EFI_PAGES_TO_SIZE (AllocatedPages));
    CopyMem (mRamBase, (VOID *)(UINTN)Start, Size);
    Size = (Size + RAM_BLOCK_SIZE - 1) / RAM_BLOCK_SIZE * RAM_BLOCK_SIZE;
  } else {
    mRamBase = (UINT8 *)(UINTN)Start;
  }

  // Owned EfiLoaderData pages stay allocated while BlockIO is installed.
  // There is no unload entry point; reclaim them only if installation fails.
  mMedia.MediaId          = 1;
  mMedia.RemovableMedia   = FALSE;
  mMedia.MediaPresent     = TRUE;
  mMedia.LogicalPartition = FALSE;
  mMedia.ReadOnly         = TRUE;
  mMedia.WriteCaching     = FALSE;
  mMedia.BlockSize        = RAM_BLOCK_SIZE;
  mMedia.IoAlign          = 1;
  mMedia.LastBlock        = Size / RAM_BLOCK_SIZE - 1;

  Status = gBS->InstallMultipleProtocolInterfaces (
                  &mRamHandle,
                  &gEfiDevicePathProtocolGuid,
                  &mDevicePath,
                  &gEfiBlockIoProtocolGuid,
                  &mBlockIo,
                  NULL
                  );
  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: initrd block device %p size 0x%lx %r\n", mRamBase, (UINT64)Size, Status));
  if (EFI_ERROR (Status)) {
    mRamHandle = NULL;
    if (AllocatedPages != 0) {
      gBS->FreePages (AllocatedBase, AllocatedPages);
    }

    mRamBase = NULL;
  }
}

EFI_STATUS
EFIAPI
UniXNURamDiskDxeEntry (
  IN EFI_HANDLE        ImageHandle,
  IN EFI_SYSTEM_TABLE  *SystemTable
  )
{
  EFI_HOB_GUID_TYPE  *Hob;
  UINT64             Dtb;

  Hob = GetFirstGuidHob (&mEntryArgHobGuid);
  if (Hob == NULL) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: no entry argument HOB\n"));
    return EFI_SUCCESS;
  }

  if (GET_GUID_HOB_DATA_SIZE (Hob) < sizeof (UINT64)) {
    return EFI_COMPROMISED_DATA;
  }

  Dtb = ReadUnaligned64 ((CONST UINT64 *)GET_GUID_HOB_DATA (Hob));
  if ((Dtb == 0) || ((Dtb & 3) != 0) || (FdtCheckHeader ((VOID *)(UINTN)Dtb) != 0)) {
    DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: x0 0x%lx is not a device tree\n", Dtb));
    return EFI_SUCCESS;
  }

  DEBUG ((DEBUG_ERROR, "UNIXNURAMDISK: device tree at 0x%lx, %u bytes\n", Dtb, (UINT32)FdtTotalSize ((VOID *)(UINTN)Dtb)));

  PublishInitrd ((VOID *)(UINTN)Dtb);
  return EFI_SUCCESS;
}
