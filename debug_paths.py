"""script to show what file_path values actually look like in the MFT"""
import struct, os

MFT_RECORD_SIZE = 1024
WINDOWS_EPOCH  = __import__('datetime').datetime(1601, 1, 1, tzinfo=__import__('datetime').timezone.utc)

def filetime_to_dt(ft):
    if ft == 0: return None
    try: return WINDOWS_EPOCH + __import__('datetime').timedelta(microseconds=ft//10)
    except: return None

def parse_record(raw, n):
    if len(raw) < 1024 or raw[:4] != b'FILE': return None
    try:
        d = bytearray(raw)
        if not (struct.unpack_from('<H', d, 22)[0] & 0x01): return None
        off = struct.unpack_from('<H', d, 20)[0]
        name = ""
        while off < 1024 - 8:
            at = struct.unpack_from('<I', d, off)[0]
            if at == 0xFFFFFFFF: break
            al = struct.unpack_from('<I', d, off+4)[0]
            if al == 0 or al > 1024-off: break
            if d[off+8] == 0 and at == 0x30:
                co = struct.unpack_from('<H', d, off+20)[0]
                cl = struct.unpack_from('<I', d, off+16)[0]
                c = d[off+co:off+co+cl]
                if len(c) >= 66:
                    try: name = c[66:66+c[64]*2].decode('utf-16-le')
                    except: pass
            off += al
        return name if name else None
    except: return None

import sys
mft_path = sys.argv[1]
print("Sample file_path values from MFT:")
print("-"*50)
count = 0
with open(mft_path,'rb') as f:
    for i in range(os.path.getsize(mft_path)//1024):
        rec = f.read(1024)
        name = parse_record(rec, i)
        if name and count < 50:
            print(f"  [{i}] {repr(name)}")
            count += 1
        if count >= 50: break
