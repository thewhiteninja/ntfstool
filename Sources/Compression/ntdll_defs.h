#pragma once

#include <Windows.h>

typedef NTSTATUS(__stdcall* _RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

typedef NTSTATUS(__stdcall* _RtlDecompressBuffer)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize
	);

typedef NTSTATUS(__stdcall* _RtlDecompressBufferEx)(
	USHORT CompressionFormat,
	PUCHAR UncompressedBuffer,
	ULONG UncompressedBufferSize,
	PUCHAR CompressedBuffer,
	ULONG CompressedBufferSize,
	PULONG FinalUncompressedSize,
	PVOID  WorkSpace
	);

typedef NTSTATUS(__stdcall* _RtlGetCompressionWorkSpaceSize)(
	USHORT CompressionFormatAndEngine,
	PULONG CompressBufferWorkSpaceSize,
	PULONG CompressFragmentWorkSpaceSize
	);

typedef NTSTATUS(__stdcall* _RtlDecompressFragment)(
	USHORT CompressionFormat,
	PUCHAR UncompressedFragment,
	ULONG  UncompressedFragmentSize,
	PUCHAR CompressedBuffer,
	ULONG  CompressedBufferSize,
	ULONG  FragmentOffset,
	PULONG FinalUncompressedSize,
	PVOID  WorkSpace
	);


