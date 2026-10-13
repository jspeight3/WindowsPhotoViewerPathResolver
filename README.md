# Windows Photo Viewer Path Resolver

A C# utility for recovering the full filesystem path of an image currently open in Windows Photo Viewer on Windows 8.1.

Windows Photo Viewer normally exposes the image filename in its window title, but not the complete path. This project searches the viewer process's readable memory for Windows Shell PIDLs (Item ID Lists) and resolves them into filesystem paths using `SHGetPathFromIDListW`.

## Features

- Automatically locates candidate PIDLs without hardcoded memory addresses.
- Supports local drive paths and UNC network paths.
- Works with images that have remained open for extended periods.
- Validates filenames and file existence.
- Recognizes different path aliases referring to the same file using Windows file identity information.
- Returns `SUCCESS`, `UNRESOLVED`, or `AMBIGUOUS`.
- Uses native Windows APIs through C# P/Invoke; no Python dependency.

## Requirements

- Windows 8.1 x64 (tested)
- Windows PowerShell 5.1 or a compatible .NET Framework 4.x application
- Permission to read the Windows Photo Viewer process's memory

## Usage

Load the source in PowerShell:

```powershell
Add-Type -Path ".\PhotoViewerPidlNative-CANDIDATE.cs"

$result = [PhotoViewerPidlNativeCandidate]::Resolve(
    1234,
    "example.png"
)

$result.Status
$result.DocumentPath
```

Replace `1234` with the Photo Viewer process ID and `example.png` with the displayed filename.

The class can also be included in a C# .NET Framework application.

## Testing

Successfully tested on Windows 8.1 x64 with four Photo Viewer windows: two local images and two UNC network images.

All four paths were recovered and subsequently used to restore their respective windows.

## Limitations

- Other Windows versions and configurations have not been validated.
- The target process must be running and its memory readable.
- The image file must still exist and be accessible.
- Different files sharing the same filename in one process may produce an ambiguous result.
- PIDL detection depends on observed Windows Photo Viewer memory structures.
- This is not a universal resolver for arbitrary applications.

## Implementation

Uses `OpenProcess`, `VirtualQueryEx`, `ReadProcessMemory`, `SHGetPathFromIDListW`, and `GetFileInformationByHandle`.

The resolver does not write to the target process's memory.

## Status

Working proof of concept validated on Windows 8.1 x64. Additional testing and contributions are welcome.
