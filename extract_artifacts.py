"""
NTFS Artifact Extractor
Extracts $MFT, $UsnJrnl:$J, and $LogFile from a live Windows system or disk image.

USAGE:
  # On a live Windows system (run as Administrator):
  python extract_artifacts.py --live --output ./artifacts/

  # From a disk image using The Sleuth Kit (tsk):
  python extract_artifacts.py --image disk.img --output ./artifacts/

  # Extract only specific artifacts:
  python extract_artifacts.py --live --only mft usn
"""

import os
import sys
import argparse
import subprocess
import platform
import shutil
from pathlib import Path

OUTPUT_DIR = "./artifacts"


# ─────────────────────────────────────────────
# LIVE WINDOWS EXTRACTION
# ─────────────────────────────────────────────

def extract_live_windows(output_dir: str, artifacts: list):
    """
    Extract NTFS artifacts from a live Windows system.
    Requires Administrator privileges.
    Uses RawCopy or direct volume access via Python.
    """
    if platform.system() != "Windows":
        print("[!] Live extraction only works on Windows.")
        return False
    
    os.makedirs(output_dir, exist_ok=True)
    
    # Method: Use fsutil / robocopy / volume shadow
    # Most reliable: use a tool like RawCopy.exe or Arsenal Image Mounter
    # Here we use the Windows Volume GUID path approach
    
    volume = r"\\.\C:"  # Change if needed
    
    # Map of NTFS metadata files and their MFT record numbers
    ntfs_files = {
        "mft":  (r"\\.\C:\$MFT",          "mft.bin"),
        "usn":  (r"\\.\C:\$Extend\$UsnJrnl:$J", "usnjrnl_J.bin"),
        "log":  (r"\\.\C:\$LogFile",       "logfile.bin"),
    }
    
    for artifact_key, (source, dest_name) in ntfs_files.items():
        if artifact_key not in artifacts:
            continue
        
        dest = os.path.join(output_dir, dest_name)
        print(f"[*] Extracting {source} → {dest}")
        
        # Try using Python's raw volume access
        success = _raw_copy_windows(source, dest)
        
        if success:
            size = os.path.getsize(dest)
            print(f"[+] Done: {dest} ({size:,} bytes)")
        else:
            print(f"[!] Failed to extract {source}")
            print(f"    Try using RawCopy64.exe or FTK Imager instead.")
    
    return True


def _raw_copy_windows(source_path: str, dest_path: str, chunk_size: int = 1024*1024) -> bool:
    """
    Read a raw NTFS metadata file using Windows volume access.
    Works by opening the volume directly and reading at the file's offset.
    """
    try:
        # Open the raw path using CreateFile via ctypes
        import ctypes
        import ctypes.wintypes
        
        GENERIC_READ = 0x80000000
        FILE_SHARE_READ = 0x1
        FILE_SHARE_WRITE = 0x2
        OPEN_EXISTING = 3
        FILE_FLAG_NO_BUFFERING = 0x20000000
        
        handle = ctypes.windll.kernel32.CreateFileW(
            source_path,
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING,
            None
        )
        
        if handle == ctypes.wintypes.HANDLE(-1).value:
            return False
        
        with open(dest_path, 'wb') as out:
            buf = ctypes.create_string_buffer(chunk_size)
            bytes_read = ctypes.wintypes.DWORD(0)
            
            total = 0
            while True:
                success = ctypes.windll.kernel32.ReadFile(
                    handle, buf, chunk_size, 
                    ctypes.byref(bytes_read), None
                )
                if not success or bytes_read.value == 0:
                    break
                out.write(buf.raw[:bytes_read.value])
                total += bytes_read.value
                
                if total % (50 * 1024 * 1024) == 0:
                    print(f"    ... {total // 1024 // 1024} MB read")
        
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    
    except Exception as e:
        print(f"    Raw copy error: {e}")
        return False


# ─────────────────────────────────────────────
# EXTRACTION FROM DISK IMAGE (using TSK)
# ─────────────────────────────────────────────

def extract_from_image(image_path: str, output_dir: str, artifacts: list):
    """
    Extract NTFS artifacts from a disk image using The Sleuth Kit (icat).
    
    Install TSK: sudo apt install sleuthkit  (Linux)
                 brew install sleuthkit      (macOS)
    """
    os.makedirs(output_dir, exist_ok=True)
    
    if not shutil.which("icat"):
        print("[!] icat (Sleuth Kit) not found.")
        print("    Install: sudo apt install sleuthkit")
        return False
    
    # NTFS reserved MFT record numbers
    NTFS_INODE = {
        "mft":  0,   # $MFT
        "mftmirr": 1,
        "log":  2,   # $LogFile  
        "vol":  3,   # $Volume
        "attr": 4,   # $AttrDef
        "root": 5,   # . (root directory)
        "bitmap": 6, # $Bitmap
        "boot": 7,   # $Boot
        "bad":  8,   # $BadClus
        "secure": 9, # $Secure
        "upcase": 10,# $UpCase
        "extend": 11,# $Extend
    }
    
    # USN Journal is in $Extend (inode 11), entry $UsnJrnl
    if "mft" in artifacts:
        inode = NTFS_INODE["mft"]
        out = os.path.join(output_dir, "mft.bin")
        print(f"[*] Extracting $MFT (inode {inode})...")
        _run_icat(image_path, inode, out)
    
    if "log" in artifacts:
        inode = NTFS_INODE["log"]
        out = os.path.join(output_dir, "logfile.bin")
        print(f"[*] Extracting $LogFile (inode {inode})...")
        _run_icat(image_path, inode, out)
    
    if "usn" in artifacts:
        # USN Journal requires finding it within $Extend
        out = os.path.join(output_dir, "usnjrnl_J.bin")
        print(f"[*] Extracting $UsnJrnl:$J...")
        _extract_usn_from_image(image_path, out)
    
    return True


def _run_icat(image_path: str, inode: int, output_path: str):
    """Run icat to extract a file by inode number."""
    try:
        cmd = ["icat", "-f", "ntfs", image_path, str(inode)]
        with open(output_path, 'wb') as f:
            result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
        
        if result.returncode == 0:
            size = os.path.getsize(output_path)
            print(f"[+] Extracted: {output_path} ({size:,} bytes)")
        else:
            print(f"[!] icat failed: {result.stderr.decode()}")
    
    except Exception as e:
        print(f"[!] Error running icat: {e}")


def _extract_usn_from_image(image_path: str, output_path: str):
    """Extract $UsnJrnl:$J from disk image."""
    try:
        # Use fls to find the USN journal entry in $Extend
        fls = subprocess.run(
            ["fls", "-f", "ntfs", "-r", image_path, "11"],
            capture_output=True, text=True
        )
        
        usn_inode = None
        for line in fls.stdout.splitlines():
            if "$UsnJrnl" in line and ":$J" in line:
                # Parse inode from line like: r/r 39-128-4: $UsnJrnl:$J
                parts = line.split()
                if len(parts) >= 3:
                    inode_str = parts[2].rstrip(':').split('-')[0]
                    try:
                        # The :$J data stream is attribute type 128 (DATA)
                        usn_inode = f"{inode_str}-128-4"
                    except ValueError:
                        pass
                break
        
        if usn_inode:
            cmd = ["icat", "-f", "ntfs", image_path, usn_inode]
            with open(output_path, 'wb') as f:
                result = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE)
            
            if result.returncode == 0:
                size = os.path.getsize(output_path)
                print(f"[+] Extracted: {output_path} ({size:,} bytes)")
            else:
                print(f"[!] Failed: {result.stderr.decode()}")
        else:
            print("[!] Could not locate $UsnJrnl:$J in $Extend directory")
    
    except Exception as e:
        print(f"[!] Error extracting USN Journal: {e}")


# ─────────────────────────────────────────────
# QUICK COLLECTION SCRIPT FOR WINDOWS
# ─────────────────────────────────────────────

POWERSHELL_COLLECTION_SCRIPT = r"""
# NTFS Artifact Collector — Run as Administrator on target Windows system
# Requires: RawCopy64.exe (download from https://github.com/jschicht/RawCopy)

param(
    [string]$OutputDir = "C:\NTFS_Artifacts",
    [string]$RawCopyPath = ".\RawCopy64.exe"
)

Write-Host "[*] NTFS Artifact Collector" -ForegroundColor Cyan
Write-Host "[*] Output directory: $OutputDir"

New-Item -ItemType Directory -Force -Path $OutputDir | Out-Null

# Extract $MFT
Write-Host "[*] Extracting `$MFT..." -ForegroundColor Yellow
& $RawCopyPath /FileNamePath:C:\$MFT /OutputPath:$OutputDir

# Extract $LogFile
Write-Host "[*] Extracting `$LogFile..." -ForegroundColor Yellow
& $RawCopyPath /FileNamePath:C:\$LogFile /OutputPath:$OutputDir

# Extract $UsnJrnl:$J
Write-Host "[*] Extracting `$UsnJrnl:J..." -ForegroundColor Yellow
& $RawCopyPath /FileNamePath:C:\$Extend\$UsnJrnl /OutputPath:$OutputDir /DataStream:J

Write-Host "[+] Collection complete!" -ForegroundColor Green
Write-Host "[+] Files saved to: $OutputDir" -ForegroundColor Green

# List collected artifacts
Get-ChildItem $OutputDir | Format-Table Name, Length -AutoSize
"""


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NTFS Artifact Extractor")
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live",  action="store_true", help="Extract from live Windows system (run as Admin)")
    group.add_argument("--image", help="Path to disk image (.img, .dd, .E01)")
    group.add_argument("--ps",    action="store_true", help="Print PowerShell collection script")
    
    parser.add_argument("--output", default="./artifacts", help="Output directory")
    parser.add_argument("--only",   nargs="+", 
                        choices=["mft", "usn", "log"], 
                        default=["mft", "usn", "log"],
                        help="Which artifacts to extract")
    
    args = parser.parse_args()
    
    if args.ps:
        print(POWERSHELL_COLLECTION_SCRIPT)
        sys.exit(0)
    
    if args.live:
        extract_live_windows(args.output, args.only)
    elif args.image:
        extract_from_image(args.image, args.output, args.only)
    
    print(f"\n[+] Artifacts ready in: {args.output}")
    print(f"[+] Now run: python detector.py --mft {args.output}/mft.bin "
          f"--usn {args.output}/usnjrnl_J.bin "
          f"--logfile {args.output}/logfile.bin")
"""
