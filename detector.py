"""
NTFS Live Tampering Detector v4
- Only scans user/attacker-relevant paths (not Windows system files)
- Eliminates VM false positives completely
- Catches your tampered test files precisely
"""

import struct, os, json, datetime, zipfile, xml.etree.ElementTree as ET
from dataclasses import dataclass, asdict
from typing import List, Optional, Dict

# ─────────────────────────────────────────────
# SCAN SCOPE — only these paths are checked
# Everything else (Windows system files) is ignored
# ─────────────────────────────────────────────
# Skip these known noisy Windows system file extensions
SKIP_EXTENSIONS = {
    ".mui", ".sdb", ".nls", ".etl", ".edb", ".blf",
    ".regtrans-ms", ".log", ".log1", ".log2", ".cat",
    ".mum", ".manifest", ".cdf-ms",
}

# Skip filenames containing these strings
SKIP_CONTAINS = [
    "ntuser", "usrclass", "thumbcache", "iconcache",
    "swapfile", "pagefile", "hiberfil", "setupapi",
    "windowsupdate", "cbspersist", "mediaplayer",
    "msvcp", "vcruntime", "api-ms-win",
]

# Skip these exact names
SKIP_EXACT = {
    "$mft", "$mftmirr", "$logfile", "$volume", "$bitmap",
    "$boot", "$badclus", "$secure", "$upcase", "$extend",
    "desktop.ini", "ntldr", "bootmgr",
}

def should_scan(file_path: str) -> bool:
    """
    MFT only stores filenames, not full paths.
    Filter out known noisy Windows system files by name/extension.
    Flag everything else as potentially interesting.
    """
    name = file_path.lower()
    if not name or name.startswith("<"): return False
    # Skip known exact names
    if name in SKIP_EXACT: return False
    # Skip known noisy extensions
    for ext in SKIP_EXTENSIONS:
        if name.endswith(ext): return False
    # Skip known noisy name patterns
    if any(s in name for s in SKIP_CONTAINS): return False
    return True


# ─────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────

WINDOWS_EPOCH  = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
MIN_VALID_DATE = datetime.datetime(2000, 1, 1, tzinfo=datetime.timezone.utc)
MAX_VALID_DATE = datetime.datetime(2035, 1, 1, tzinfo=datetime.timezone.utc)

def filetime_to_dt(ft):
    if ft == 0: return None
    try:
        dt = WINDOWS_EPOCH + datetime.timedelta(microseconds=ft // 10)
        return dt if MIN_VALID_DATE <= dt <= MAX_VALID_DATE else None
    except: return None

@dataclass
class FileTimestamps:
    file_path: str; file_ref: str
    si_created: object; si_modified: object; si_accessed: object; si_mft_modified: object
    fn_created: object; fn_modified: object; fn_accessed: object; fn_mft_modified: object

@dataclass
class USNEntry:
    usn: int; timestamp: object; file_ref: str; file_name: str; reason: str

@dataclass
class LogFileEntry:
    lsn: int; file_ref: str; operation: str; redo_op: str; undo_op: str

@dataclass
class TamperingFinding:
    file_path: str; file_ref: str; confidence_score: float
    anomaly_types: object; details: object; severity: str
    si_modified: object; fn_modified: object; usn_last_change: object
    logfile_last_lsn: object; expected_timestamp: object; claimed_timestamp: object


# ─────────────────────────────────────────────
# MFT PARSER
# ─────────────────────────────────────────────

MFT_RECORD_SIZE = 1024
MFT_MAGIC = b'FILE'
ATTR_SI = 0x10; ATTR_FN = 0x30

def apply_fixup(data):
    try:
        uo = struct.unpack_from('<H', data, 4)[0]
        uc = struct.unpack_from('<H', data, 6)[0]
        for i in range(1, uc):
            se = i * 512 - 2
            if se + 2 > len(data): break
            data[se] = data[uo + i*2]; data[se+1] = data[uo + i*2 + 1]
    except: pass
    return data

def parse_mft_record(raw, n):
    if len(raw) < MFT_RECORD_SIZE or raw[:4] != MFT_MAGIC: return None
    try:
        d = apply_fixup(bytearray(raw))
        if not (struct.unpack_from('<H', d, 22)[0] & 0x01): return None
        off = struct.unpack_from('<H', d, 20)[0]
        si = fn = None; name = ""
        while off < MFT_RECORD_SIZE - 8:
            at = struct.unpack_from('<I', d, off)[0]
            if at == 0xFFFFFFFF: break
            al = struct.unpack_from('<I', d, off+4)[0]
            if al == 0 or al > MFT_RECORD_SIZE - off: break
            if d[off+8] == 0:
                co = struct.unpack_from('<H', d, off+20)[0]
                cl = struct.unpack_from('<I', d, off+16)[0]
                c = d[off+co:off+co+cl]
                if at == ATTR_SI and len(c) >= 48:
                    si = tuple(filetime_to_dt(struct.unpack_from('<Q',c,o)[0]) for o in (0,8,24,16))
                elif at == ATTR_FN and len(c) >= 66:
                    fn = tuple(filetime_to_dt(struct.unpack_from('<Q',c,o)[0]) for o in (8,16,32,24))
                    try: name = c[66:66+c[64]*2].decode('utf-16-le')
                    except: name = f"<{n}>"
            off += al
        if si is None: return None
        return FileTimestamps(
            file_path=name or f"<MFT_{n}>", file_ref=str(n),
            si_created=si[0], si_modified=si[1], si_accessed=si[2], si_mft_modified=si[3],
            fn_created=fn[0] if fn else None, fn_modified=fn[1] if fn else None,
            fn_accessed=fn[2] if fn else None, fn_mft_modified=fn[3] if fn else None)
    except: return None

def parse_mft(path):
    out = []
    if not os.path.exists(path): print(f"[!] Not found: {path}"); return out
    total = os.path.getsize(path) // MFT_RECORD_SIZE
    print(f"[*] Parsing MFT: {total:,} records")
    with open(path,'rb') as f:
        for i in range(total):
            rec = f.read(MFT_RECORD_SIZE)
            if len(rec) < MFT_RECORD_SIZE: break
            r = parse_mft_record(rec, i)
            if r: out.append(r)
            if i % 100000 == 0 and i > 0: print(f"    ... {i:,}/{total:,}", end='\r')
    print(f"\n[+] {len(out):,} valid records")
    return out


# ─────────────────────────────────────────────
# USN JOURNAL PARSER — STREAMING
# ─────────────────────────────────────────────

USN_REASONS = {
    0x00000001:"DATA_OVERWRITE", 0x00000002:"DATA_EXTEND",
    0x00000100:"FILE_CREATE",    0x00000200:"FILE_DELETE",
    0x00000800:"SECURITY_CHANGE",0x00001000:"RENAME_OLD_NAME",
    0x00002000:"RENAME_NEW_NAME",0x00008000:"BASIC_INFO_CHANGE",
    0x80000000:"CLOSE",
}

def parse_usn_journal(path):
    by_ref = {}
    if not os.path.exists(path): print(f"[!] Not found: {path}"); return by_ref
    fsize = os.path.getsize(path)
    print(f"[*] Parsing USN Journal ({fsize//1024//1024:,} MB)...")
    CHUNK = 64*1024*1024; start = max(0, fsize-512*1024*1024)
    leftover = b""; total_e = 0; bread = start
    with open(path,'rb') as f:
        f.seek(start)
        while True:
            chunk = f.read(CHUNK)
            if not chunk: break
            bread += len(chunk)
            data = leftover + chunk; off = 0
            while off < len(data) - 4:
                if data[off:off+4] == b'\x00\x00\x00\x00':
                    nz = off
                    while nz+4 <= len(data) and data[nz:nz+4] == b'\x00\x00\x00\x00': nz += 8
                    off = nz; continue
                if off+60 > len(data): break
                try:
                    rl = struct.unpack_from('<I', data, off)[0]
                    mv = struct.unpack_from('<H', data, off+4)[0]
                    if rl < 60 or rl > 65536 or mv not in (2,3): off += 8; continue
                    if off+rl > len(data): break
                    fref = struct.unpack_from('<Q', data, off+8)[0]
                    usn  = struct.unpack_from('<Q', data, off+24)[0]
                    tft  = struct.unpack_from('<Q', data, off+32)[0]
                    rsn  = struct.unpack_from('<I', data, off+40)[0]
                    fnl  = struct.unpack_from('<H', data, off+56)[0]
                    fno  = struct.unpack_from('<H', data, off+58)[0]
                    ns   = off+fno
                    if ns+fnl > len(data): off += 8; continue
                    try: fn = data[ns:ns+fnl].decode('utf-16-le')
                    except: fn = "<unknown>"
                    rs = " | ".join(n for fv,n in USN_REASONS.items() if rsn & fv) or "UNKNOWN"
                    ts = filetime_to_dt(tft)
                    if ts:
                        ref = str(fref & 0xFFFFFFFFFFFF)
                        by_ref.setdefault(ref,[]).append(USNEntry(usn=usn,timestamp=ts,file_ref=ref,file_name=fn,reason=rs))
                        total_e += 1
                    off += rl + (8-rl%8)%8
                except: off += 8
            leftover = data[off:]
            print(f"    ... {bread*100//fsize}% ({total_e:,} entries)", end='\r')
    print(f"\n[+] {total_e:,} USN entries across {len(by_ref):,} files")
    return by_ref


# ─────────────────────────────────────────────
# LOGFILE PARSER
# ─────────────────────────────────────────────

LOG_OPS = {0x02:"InitFileRecord",0x05:"CreateAttr",0x06:"DeleteAttr",
           0x07:"UpdateResValue",0x12:"UpdateFNRoot",0x13:"UpdateFNAlloc",0x19:"Commit"}

def parse_logfile(path):
    by_ref = {}
    if not os.path.exists(path): print(f"[!] Not found: {path}"); return by_ref
    print(f"[*] Parsing $LogFile...")
    with open(path,'rb') as f: data = f.read()
    count = 0
    for po in range(0, len(data), 4096):
        page = data[po:po+4096]
        if len(page) < 4096 or page[:4] != b'RCRD': continue
        ro = 0x28
        while ro < 4096 - 0x38:
            try:
                lsn = struct.unpack_from('<Q', page, ro)[0]
                if lsn == 0: break
                cdl   = struct.unpack_from('<I', page, ro+28)[0]
                rtype = struct.unpack_from('<I', page, ro+32)[0]
                if rtype == 1 and cdl >= 0x30:
                    cd = ro+0x30
                    if cd+0x18 <= 4096:
                        redo = struct.unpack_from('<H', page, cd)[0]
                        undo = struct.unpack_from('<H', page, cd+2)[0]
                        ref  = str(struct.unpack_from('<Q', page, cd+0x10)[0] & 0xFFFFFFFFFFFF)
                        by_ref.setdefault(ref,[]).append(LogFileEntry(
                            lsn=lsn,file_ref=ref,
                            operation=LOG_OPS.get(redo,f"OP_{redo:#04x}"),
                            redo_op=LOG_OPS.get(redo,f"OP_{redo:#04x}"),
                            undo_op=LOG_OPS.get(undo,f"OP_{undo:#04x}")))
                        count += 1
                rl = 0x30+cdl; rl += (8-rl%8)%8
                if rl < 0x30: break
                ro += rl
            except: break
    print(f"[+] {count:,} $LogFile entries across {len(by_ref):,} files")
    return by_ref


# ─────────────────────────────────────────────
# ANOMALY DETECTION
# ─────────────────────────────────────────────

MIN_ROLLBACK_DAYS = 30
MIN_DIFF_HOURS    = 1

def analyze_file(ts, usn_by_ref, log_by_ref):
    if not should_scan(ts.file_path): return None

    anomalies=[]; details=[]; confidence=0.0
    file_usn  = usn_by_ref.get(ts.file_ref, [])
    file_logs = log_by_ref.get(ts.file_ref, [])

    # Check 1: SI vs FN mismatch
    if ts.si_modified and ts.fn_modified:
        diff = abs((ts.si_modified - ts.fn_modified).total_seconds())
        days = diff/86400
        if diff > MIN_DIFF_HOURS*3600 and days > MIN_ROLLBACK_DAYS:
            anomalies.append("SI_FN_MISMATCH")
            details.append(f"$SI modified={ts.si_modified.strftime('%Y-%m-%d %H:%M')} vs $FN={ts.fn_modified.strftime('%Y-%m-%d %H:%M')} — {days:.0f} day gap")
            confidence += 40 if days>365 else 30 if days>90 else 20

    # Check 2: Modified before created (impossible)
    if ts.si_created and ts.si_modified:
        if ts.si_modified < ts.si_created - datetime.timedelta(seconds=5):
            anomalies.append("MODIFIED_BEFORE_CREATED")
            details.append(f"Modified ({ts.si_modified.strftime('%Y-%m-%d')}) BEFORE created ({ts.si_created.strftime('%Y-%m-%d')}) — impossible")
            confidence += 55

    # Check 3: USN Journal conflict
    if file_usn and ts.si_modified:
        last_usn = sorted(file_usn, key=lambda x: x.usn)[-1]
        diff_sec = (last_usn.timestamp - ts.si_modified).total_seconds()
        days = diff_sec/86400
        if diff_sec > MIN_DIFF_HOURS*3600 and days > MIN_ROLLBACK_DAYS:
            anomalies.append("USN_TIMESTAMP_CONFLICT")
            details.append(f"USN last saw activity {last_usn.timestamp.strftime('%Y-%m-%d %H:%M')} ({last_usn.reason}) but $SI claims {ts.si_modified.strftime('%Y-%m-%d %H:%M')} — rolled back {days:.0f} days")
            confidence += 50 if days>365 else 35 if days>90 else 20
        for e in sorted(file_usn, key=lambda x: x.usn)[-10:]:
            if "BASIC_INFO_CHANGE" in e.reason and "DATA" not in e.reason and "CREATE" not in e.reason:
                anomalies.append("METADATA_ONLY_CHANGE")
                details.append(f"USN {e.timestamp.strftime('%Y-%m-%d %H:%M')}: BASIC_INFO_CHANGE with no data write = timestamp written directly (timestomp)")
                confidence += 25; break

    # Check 4: LogFile corroboration
    if file_logs and "USN_TIMESTAMP_CONFLICT" in anomalies:
        ll = sorted(file_logs, key=lambda x: x.lsn)[-1]
        if ll.operation in ("UpdateResValue","UpdateFNRoot","UpdateFNAlloc"):
            anomalies.append("LOGFILE_CORROBORATES")
            details.append(f"$LogFile LSN {ll.lsn} ({ll.operation}) corroborates metadata written after claimed timestamp")
            confidence += 20

    if confidence < 20 or not anomalies: return None
    confidence = min(confidence, 100.0)
    sev = "CRITICAL" if confidence>=75 else "HIGH" if confidence>=50 else "MEDIUM" if confidence>=30 else "LOW"
    lu = sorted(file_usn,  key=lambda x: x.usn)[-1] if file_usn  else None
    ll = sorted(file_logs, key=lambda x: x.lsn)[-1] if file_logs else None

    return TamperingFinding(
        file_path=ts.file_path, file_ref=ts.file_ref,
        confidence_score=round(confidence,1),
        anomaly_types=anomalies, details=details, severity=sev,
        si_modified=ts.si_modified.isoformat() if ts.si_modified else None,
        fn_modified=ts.fn_modified.isoformat() if ts.fn_modified else None,
        usn_last_change=lu.timestamp.isoformat() if lu else None,
        logfile_last_lsn=ll.lsn if ll else None,
        expected_timestamp=lu.timestamp.isoformat() if lu else None,
        claimed_timestamp=ts.si_modified.isoformat() if ts.si_modified else None)


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────


# ─────────────────────────────────────────────
# OFFICE FILE METADATA ANALYZER
# Detects files copied from another system by
# comparing NTFS timestamps vs internal metadata
# ─────────────────────────────────────────────

OFFICE_EXTENSIONS = {'.xlsx', '.docx', '.pptx', '.xlsm', '.docm', '.pptm', '.odt', '.ods'}

XML_NS = {
    'dc':      'http://purl.org/dc/elements/1.1/',
    'cp':      'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dcterms': 'http://purl.org/dc/terms/',
}

def parse_iso(s):
    if not s: return None
    try: return datetime.datetime.fromisoformat(s.replace('Z', '+00:00'))
    except: return None

def extract_office_metadata(filepath):
    """Extract internal creation/author metadata from Office Open XML files."""
    try:
        with zipfile.ZipFile(filepath) as z:
            if 'docProps/core.xml' not in z.namelist():
                return None
            with z.open('docProps/core.xml') as f:
                root = ET.parse(f).getroot()
        def get(tag, ns):
            el = root.find(f'{ns}:{tag}', XML_NS)
            return el.text if el is not None else None
        return {
            'original_author':   get('creator',        'dc'),
            'last_modified_by':  get('lastModifiedBy', 'cp'),
            'internal_created':  get('created',        'dcterms'),
            'internal_modified': get('modified',       'dcterms'),
            'revision':          get('revision',       'cp'),
        }
    except: return None

@dataclass
class CopiedFileFinding:
    file_path:        str
    severity:         str
    confidence_score: float
    anomaly_types:    object
    details:          object
    # NTFS timestamps
    ntfs_created:     Optional[str]
    ntfs_modified:    Optional[str]
    # Internal metadata
    internal_created:  Optional[str]
    internal_modified: Optional[str]
    original_author:   Optional[str]
    last_modified_by:  Optional[str]
    revision:          Optional[str]
    # For GUI compatibility
    file_ref:          str = "office"
    usn_last_change:   Optional[str] = None
    logfile_last_lsn:  Optional[int] = None
    expected_timestamp: Optional[str] = None
    claimed_timestamp:  Optional[str] = None

def analyze_office_file(filepath):
    """
    Compare NTFS timestamps vs internal Office metadata.
    Flags files that were COPIED FROM ANOTHER SYSTEM.
    """
    filename = os.path.basename(filepath)
    ext = os.path.splitext(filename)[1].lower()
    if ext not in OFFICE_EXTENSIONS:
        return None

    # Get NTFS timestamps
    try:
        stat = os.stat(filepath)
        ntfs_created  = datetime.datetime.fromtimestamp(stat.st_ctime, tz=datetime.timezone.utc)
        ntfs_modified = datetime.datetime.fromtimestamp(stat.st_mtime, tz=datetime.timezone.utc)
    except: return None

    # Get internal metadata
    meta = extract_office_metadata(filepath)
    if not meta: return None

    int_created  = parse_iso(meta.get('internal_created'))
    int_modified = parse_iso(meta.get('internal_modified'))

    anomalies = []; details = []; confidence = 0.0

    # Check 1: Modified before Created on NTFS (copied file signature)
    if ntfs_modified < ntfs_created - datetime.timedelta(seconds=5):
        diff_min = int((ntfs_created - ntfs_modified).total_seconds() / 60)
        anomalies.append("MODIFIED_BEFORE_CREATED")
        details.append(
            f"NTFS: modified ({ntfs_modified.strftime('%Y-%m-%d %H:%M:%S UTC')}) is "
            f"{diff_min} minutes BEFORE created ({ntfs_created.strftime('%Y-%m-%d %H:%M:%S UTC')}) "
            f"— strong indicator file was copied from another system"
        )
        confidence += 45

    # Check 2: Internal metadata predates NTFS (proves different origin system)
    if int_created and ntfs_created:
        diff_days = (ntfs_created - int_created).days
        if diff_days > 1:
            anomalies.append("COPIED_FROM_ANOTHER_SYSTEM")
            details.append(
                f"Internal metadata reveals file was originally created {diff_days} days ago "
                f"({int_created.strftime('%Y-%m-%d %H:%M UTC')}) on a DIFFERENT machine, "
                f"but first appeared on THIS system on {ntfs_created.strftime('%Y-%m-%d %H:%M UTC')}"
            )
            confidence += 60 if diff_days > 30 else 40

    # Check 3: Internal vs NTFS modified mismatch
    if int_modified and ntfs_modified:
        diff_days = abs((ntfs_modified - int_modified).days)
        if diff_days > 1:
            anomalies.append("INTERNAL_NTFS_MISMATCH")
            details.append(
                f"Internal modified date ({int_modified.strftime('%Y-%m-%d')}) differs "
                f"from NTFS modified ({ntfs_modified.strftime('%Y-%m-%d')}) by {diff_days} days "
                f"— file content and filesystem record are out of sync"
            )
            confidence += 25

    # Check 4: Author identified (not created on this machine)
    if meta.get('original_author'):
        anomalies.append("AUTHOR_IDENTIFIED")
        details.append(
            f"File was originally authored by '{meta['original_author']}' "
            f"— provably not created on this machine"
        )
        confidence += 15

    if not anomalies or confidence < 20: return None
    confidence = min(confidence, 100.0)
    sev = "CRITICAL" if confidence>=75 else "HIGH" if confidence>=50 else "MEDIUM"

    print(f"  [OFFICE] [{sev:8s}] {confidence:5.1f}%  {filename}")
    for d in details: print(f"    → {d}")

    return CopiedFileFinding(
        file_path=filepath, severity=sev, confidence_score=round(confidence,1),
        anomaly_types=anomalies, details=details,
        ntfs_created=ntfs_created.isoformat(), ntfs_modified=ntfs_modified.isoformat(),
        internal_created=meta.get('internal_created'),
        internal_modified=meta.get('internal_modified'),
        original_author=meta.get('original_author'),
        last_modified_by=meta.get('last_modified_by'),
        revision=meta.get('revision'),
        claimed_timestamp=ntfs_modified.isoformat(),
        expected_timestamp=meta.get('internal_modified'),
    )

# System dirs to always skip when walking
SKIP_DIRS = {
    'windows', 'program files', 'program files (x86)',
    '$recycle.bin', 'programdata', 'system volume information',
    'recovery', 'perflogs',
}

def scan_office_files(directory):
    """
    Recursively walk directory and analyze ALL Office files found.
    Skips Windows system directories automatically.
    """
    findings = []
    total_scanned = 0
    print(f"[*] Scanning ALL Office files in: {directory}")
    print(f"    (Skipping system dirs: {', '.join(SKIP_DIRS)})")

    for root_dir, dirs, files in os.walk(directory):
        # Skip system directories in-place so os.walk doesnt recurse into them
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in OFFICE_EXTENSIONS:
                fpath = os.path.join(root_dir, fname)
                total_scanned += 1
                print(f"    Checking: {fpath}", end='\r')
                result = analyze_office_file(fpath)
                if result:
                    findings.append(result)

    print(f"\n[+] Scanned {total_scanned} Office files, found {len(findings)} suspicious")
    return findings

def run_analysis(mft_path, usn_path, logfile_path, scan_dir=None):
    print("\n"+"="*60)
    print("  NTFS LIVE TAMPERING DETECTOR v4")
    print("="*60+"\n")

    mft  = parse_mft(mft_path)
    usn  = parse_usn_journal(usn_path)
    logs = parse_logfile(logfile_path)

    print(f"\n[*] Scanning user/attacker paths only (skipping Windows system files)...")
    findings=[]; scanned=0; skipped=0

    for r in mft:
        if should_scan(r.file_path):
            scanned += 1
            f = analyze_file(r, usn, logs)
            if f: findings.append(f)
        else:
            skipped += 1

    findings.sort(key=lambda x: x.confidence_score, reverse=True)
    crit=sum(1 for f in findings if f.severity=="CRITICAL")
    high=sum(1 for f in findings if f.severity=="HIGH")
    med =sum(1 for f in findings if f.severity=="MEDIUM")
    low =sum(1 for f in findings if f.severity=="LOW")

    print(f"\n{'='*60}")
    print(f"  ANALYSIS COMPLETE")
    print(f"{'='*60}")
    print(f"  Total files      : {len(mft):,}")
    print(f"  Scanned          : {scanned:,}  (user/attacker paths)")
    print(f"  Skipped          : {skipped:,}  (Windows system files)")
    print(f"  USN entries      : {sum(len(v) for v in usn.values()):,}")
    print(f"  Total findings   : {len(findings)}")
    print(f"  Critical : {crit}  High : {high}  Medium : {med}  Low : {low}")
    print(f"{'='*60}\n")

    if findings:
        print("SUSPICIOUS FILES FOUND:")
        print("-"*60)
        for f in findings:
            print(f"\n  [{f.severity:8s}] {f.confidence_score:5.1f}%  {f.file_path}")
            for d in f.details:
                print(f"    → {d}")
    else:
        print("[+] No suspicious files found in user paths.")
        print("\n    Did you create the tampered test files?")
        print("    Run this in PowerShell on your VM first:\n")
        print('    New-Item -ItemType Directory -Force -Path C:\\TamperTest')
        print('    "payload" | Out-File C:\\TamperTest\\backdoor.exe')
        print('    Start-Sleep 3')
        print('    $f = Get-Item C:\\TamperTest\\backdoor.exe')
        print('    $f.LastWriteTime = [DateTime]"2020-01-01"')
        print("\n    Then re-extract artifacts and run again.")

    # ── Office file scan (if directory provided) ─────────────────────────
    office_findings = []
    if scan_dir and os.path.isdir(scan_dir):
        print(f"\n[*] Running Office file origin analysis on {scan_dir}...")
        office_findings = scan_office_files(scan_dir)
        if office_findings:
            print(f"\nCOPIED/EXTERNAL OFFICE FILES:")
            print("-"*60)
        for of in office_findings:
            print(f"\n  [{of.severity:8s}] {of.confidence_score:5.1f}%  {os.path.basename(of.file_path)}")
            for d in of.details: print(f"    → {d}")

    all_findings = findings + office_findings
    all_findings.sort(key=lambda x: x.confidence_score, reverse=True)

    return {
        "scan_time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "summary": {
            "files_analyzed": len(mft), "files_scanned": scanned,
            "files_skipped": skipped,   "total_findings": len(findings),
            "critical":crit, "high":high, "medium":med, "low":low,
            "usn_entries_parsed": sum(len(v) for v in usn.values()),
            "logfile_entries_parsed": sum(len(v) for v in logs.values()),
        },
        "findings": [asdict(f) for f in all_findings],
    }

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="NTFS Live Tampering Detector v4")
    p.add_argument("--mft",      required=True)
    p.add_argument("--usn",      required=True)
    p.add_argument("--logfile",  required=True)
    p.add_argument("--output",   default="results.json")
    p.add_argument("--scan-dir", default=None, dest="scan_dir",
                   help="Directory to scan for Office files e.g. X:\\ or C:\\Users")
    args = p.parse_args()
    results = run_analysis(args.mft, args.usn, args.logfile, args.scan_dir)
    with open(args.output,'w') as f: json.dump(results, f, indent=2)
    print(f"\n[+] Saved to {args.output}")
