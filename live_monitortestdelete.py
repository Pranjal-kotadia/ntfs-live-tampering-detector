"""
NTFS Live Tampering Monitor v5 — USN Journal + $LogFile + MFT corroboration
- Detection 4 rewritten: no longer relies on session_age race condition
  Now triggers on ANY FILE_CREATE + DATA_EXTEND + CLOSE seen live,
  regardless of when the monitor started. Uses GetFileInformationByHandle
  to read real NTFS creation time and compares to file's own LastWriteTime
  to catch copies where source timestamp is much older than arrival time.

Run as Administrator:
    python live_monitor.py
    python live_monitor.py --drive X
    python live_monitor.py --drive X --output alerts.json
"""

import ctypes, ctypes.wintypes, struct, datetime, time, sys, os, json
from collections import defaultdict

# ── Extra ioctl for MFT/LogFile corroboration ─────────────────────────────────
FSCTL_GET_NTFS_VOLUME_DATA = 0x00090064
FILE_FLAG_NO_BUFFERING     = 0x20000000
FILE_FLAG_RANDOM_ACCESS    = 0x10000000
FILE_SHARE_ALL             = 0x00000007

ATTR_STANDARD_INFORMATION = 0x10
ATTR_FILE_NAME            = 0x30
ATTR_END                  = 0xFFFFFFFF
FNAME_WIN32               = 1
FNAME_WIN32DOS            = 3

GENERIC_READ     = 0x80000000
FILE_SHARE_READ  = 0x00000001
FILE_SHARE_WRITE = 0x00000002
OPEN_EXISTING    = 3
FSCTL_QUERY_USN_JOURNAL = 0x000900F4
FSCTL_READ_USN_JOURNAL  = 0x000900BB

WINDOWS_EPOCH = datetime.datetime(1601,1,1,tzinfo=datetime.timezone.utc)

REASONS = {
    0x00000001:"DATA_OVERWRITE", 0x00000002:"DATA_EXTEND",
    0x00000004:"DATA_TRUNCATION",0x00000100:"FILE_CREATE",
    0x00000200:"FILE_DELETE",    0x00008000:"BASIC_INFO_CHANGE",
    0x00001000:"RENAME_OLD_NAME",0x00002000:"RENAME_NEW_NAME",
    0x80000000:"CLOSE"
}

# Extensions that are always noisy (system/browser internals)
IGNORE_EXTENSIONS = {
    ".ldb", ".log", ".tmp", ".pf", ".db", ".db-wal", ".db-shm",
    ".etl", ".evtx", ".mui", ".dat", ".blf", ".regtrans-ms",
    ".manifest", ".cat", ".fbs",
}

# Exact filenames that are always noisy (browser atomic-save targets)
IGNORE_EXACT = {
    "preferences", "secure preferences", "local state",
    "cookies", "history", "bookmarks", "shortcuts",
    "visited links", "top sites", "web data",
    "network persistent state", "last session", "last tabs",
    "current session", "current tabs", "login data",
    "favicons", "transport security", "trust tokens",
    "ntuser.dat", "usrclass.dat", "schema.fbs",
    "rules.fbs", "rules.json", "log.old",
}

# Substrings in filenames that indicate browser/system temp operations
IGNORE_CONTAINS = {
    "~rf", ".tmp.", "temp-", "-journal", "-wal", "-shm",
    "crashpad", "recovery", "gpuprocess", "zxcvbn",
}

# Blank Office template names — Windows creates these with a stray
# BASIC_INFO_CHANGE immediately after save. They are never suspicious
# regardless of which detection fires, so we suppress them at the
# is_noisy() gate before any detection logic runs at all.
# Substrings so "New Microsoft Excel Worksheet (2).xlsx" is also caught.
IGNORE_OFFICE_TEMPLATES = {
    "new microsoft excel worksheet",
    "new microsoft word document",
    "new microsoft powerpoint presentation",
    "new microsoft access database",
    "book1.xlsx", "sheet1.xlsx",
    "document1.docx", "presentation1.pptx",
}

def is_noisy(fname):
    fl = fname.lower()
    # Exact match
    if fl in IGNORE_EXACT:
        return True
    # Extension match
    for ext in IGNORE_EXTENSIONS:
        if fl.endswith(ext):
            return True
    # Substring match
    for sub in IGNORE_CONTAINS:
        if sub in fl:
            return True
    # Blank Office template names — suppress ALL events for these files
    for t in IGNORE_OFFICE_TEMPLATES:
        if t in fl:
            return True
    return False

def decode(r):
    return " | ".join(n for f,n in REASONS.items() if r&f) or "UNKNOWN"

class READ_USN_DATA(ctypes.Structure):
    _fields_ = [
        ("StartUsn",          ctypes.c_int64),
        ("ReasonMask",        ctypes.c_uint32),
        ("ReturnOnlyOnClose", ctypes.c_uint32),
        ("Timeout",           ctypes.c_uint64),
        ("BytesToWaitFor",    ctypes.c_uint64),
        ("UsnJournalID",      ctypes.c_uint64),
    ]

class USN_JOURNAL_DATA(ctypes.Structure):
    _fields_ = [
        ("UsnJournalID",    ctypes.c_uint64),
        ("FirstUsn",        ctypes.c_int64),
        ("NextUsn",         ctypes.c_int64),
        ("LowestValidUsn",  ctypes.c_int64),
        ("MaxUsn",          ctypes.c_int64),
        ("MaximumSize",     ctypes.c_uint64),
        ("AllocationDelta", ctypes.c_uint64),
    ]

os.system("")
RED    = "\033[91m"; YELLOW = "\033[93m"; CYAN = "\033[96m"
GREEN  = "\033[92m"; DIM    = "\033[2m";  BOLD = "\033[1m"; RST = "\033[0m"

def print_banner(drive):
    print("\033[2J\033[H")
    print(BOLD + "="*65 + RST)
    print(BOLD + CYAN + "  NTFS LIVE TAMPERING MONITOR v3" + RST)
    print(DIM  + f"  Watching {drive}:\\ USN Journal for real-time timestamp attacks" + RST)
    print(BOLD + "="*65 + RST)
    print()

def print_alert(alert):
    sev_color = RED if alert["severity"] == "CRITICAL" else YELLOW
    print(f"\n{sev_color}{BOLD}{'!'*65}{RST}")
    print(f"{sev_color}{BOLD}  🚨 [{alert['time'][11:19]}] {alert['alert_type']}{RST}")
    print(f"{sev_color}  File     : {alert['file_name']}{RST}")
    print(f"{sev_color}  Severity : {alert['severity']}{RST}")
    print(f"  Detail   : {alert['detail']}")
    if alert.get("claimed_ts") and alert.get("actual_ts"):
        print(f"  Claimed  : {RED}{alert['claimed_ts']}{RST}  (what attacker set)")
        print(f"  Actual   : {GREEN}{alert['actual_ts']}{RST}  (when file really changed)")
    print(f"{sev_color}{BOLD}{'!'*65}{RST}\n")

# ── Per-file state tracker ────────────────────────────────────────────────────
class FileState:
    def __init__(self):
        self.history         = []   # (time, reason, fname)
        self.created_at      = None
        self.last_data_write = None
        self.reasons_seen    = set()  # all reason flags seen since FILE_CREATE
        self.close_seen      = False
        self.alerted_copy    = False  # avoid double-alerting same file
        self.last_fname      = None   # most recent filename seen for this ref
        self.rename_old_time = None   # when RENAME_OLD_NAME last fired
        self.rename_old_name = None   # filename at time of RENAME_OLD_NAME
        self.alerted_delete  = False  # avoid double-alerting deletes


# ── Helpers ───────────────────────────────────────────────────────────────────

# BY_HANDLE_FILE_INFORMATION struct for GetFileInformationByHandle
class BY_HANDLE_FILE_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("dwFileAttributes",     ctypes.wintypes.DWORD),
        ("ftCreationTime",       ctypes.wintypes.FILETIME),
        ("ftLastAccessTime",     ctypes.wintypes.FILETIME),
        ("ftLastWriteTime",      ctypes.wintypes.FILETIME),
        ("dwVolumeSerialNumber", ctypes.wintypes.DWORD),
        ("nFileSizeHigh",        ctypes.wintypes.DWORD),
        ("nFileSizeLow",         ctypes.wintypes.DWORD),
        ("nNumberOfLinks",       ctypes.wintypes.DWORD),
        ("nFileIndexHigh",       ctypes.wintypes.DWORD),
        ("nFileIndexLow",        ctypes.wintypes.DWORD),
    ]

# ── NTFS volume data struct (from mft_scanner) ───────────────────────────────
class NTFS_VOLUME_DATA(ctypes.Structure):
    _fields_ = [
        ("VolumeSerialNumber",           ctypes.c_int64),
        ("NumberSectors",                ctypes.c_int64),
        ("TotalClusters",                ctypes.c_int64),
        ("FreeClusters",                 ctypes.c_int64),
        ("TotalReserved",                ctypes.c_int64),
        ("BytesPerSector",               ctypes.c_uint32),
        ("BytesPerCluster",              ctypes.c_uint32),
        ("BytesPerFileRecordSegment",    ctypes.c_uint32),
        ("ClustersPerFileRecordSegment", ctypes.c_uint32),
        ("MftValidDataLength",           ctypes.c_int64),
        ("MftStartLcn",                  ctypes.c_int64),
        ("Mft2StartLcn",                 ctypes.c_int64),
        ("MftZoneStart",                 ctypes.c_int64),
        ("MftZoneEnd",                   ctypes.c_int64),
    ]


def ft_raw_to_dt(raw_ft):
    """Convert raw 64-bit FILETIME integer to UTC datetime."""
    if raw_ft == 0:
        return None
    try:
        return WINDOWS_EPOCH + datetime.timedelta(microseconds=raw_ft // 10)
    except Exception:
        return None


def apply_fixup(record, sector_size=512):
    if len(record) < 48:
        return record
    record = bytearray(record)
    usa_off   = struct.unpack_from("<H", record, 4)[0]
    usa_count = struct.unpack_from("<H", record, 6)[0]
    if usa_off + usa_count * 2 > len(record):
        return bytes(record)
    seq_num = struct.unpack_from("<H", record, usa_off)[0]
    for i in range(1, usa_count):
        pos = i * sector_size - 2
        if pos + 2 > len(record):
            break
        replacement = struct.unpack_from("<H", record, usa_off + i * 2)[0]
        struct.pack_into("<H", record, pos, replacement)
    return bytes(record)


def parse_mft_record_quick(raw):
    """
    Lightweight MFT record parser — extracts only what we need for
    live corroboration: $SI timestamps, $FN timestamps, LSN.
    Returns dict or None.
    """
    if not raw or len(raw) < 48 or raw[:4] != b'FILE':
        return None
    raw = apply_fixup(raw)
    flags   = struct.unpack_from("<H", raw, 22)[0]
    if not (flags & 0x01):   # not in-use
        return None
    lsn     = struct.unpack_from("<q", raw, 8)[0]
    attr_off = struct.unpack_from("<H", raw, 20)[0]
    result = {
        "lsn":          abs(lsn),
        "si_created":   None, "si_modified":  None,
        "fn_created":   None, "fn_modified":  None,
        "fn_name":      None,
    }
    fn_candidates = []
    off = attr_off
    while off + 8 <= len(raw):
        atype = struct.unpack_from("<I", raw, off)[0]
        if atype == ATTR_END or atype == 0:
            break
        alen = struct.unpack_from("<I", raw, off + 4)[0]
        if alen == 0 or off + alen > len(raw):
            break
        if raw[off + 8] == 0:   # resident
            clen = struct.unpack_from("<I", raw, off + 16)[0]
            coff = struct.unpack_from("<H", raw, off + 20)[0]
            cs   = off + coff
            ce   = cs + clen
            if cs < len(raw) and ce <= len(raw):
                c = raw[cs:ce]
                if atype == ATTR_STANDARD_INFORMATION and len(c) >= 48:
                    result["si_created"]  = ft_raw_to_dt(struct.unpack_from("<Q", c, 0)[0])
                    result["si_modified"] = ft_raw_to_dt(struct.unpack_from("<Q", c, 8)[0])
                elif atype == ATTR_FILE_NAME and len(c) >= 66:
                    fn_cre  = ft_raw_to_dt(struct.unpack_from("<Q", c, 8)[0])
                    fn_mod  = ft_raw_to_dt(struct.unpack_from("<Q", c, 16)[0])
                    ns      = c[65]
                    fnl     = c[64]
                    try:    nm = c[66:66+fnl*2].decode("utf-16-le")
                    except: nm = None
                    fn_candidates.append({"ns": ns, "fn_created": fn_cre,
                                          "fn_modified": fn_mod, "fn_name": nm})
        off += alen
    if fn_candidates:
        best = sorted(fn_candidates, key=lambda x: 0 if x["ns"] in (FNAME_WIN32, FNAME_WIN32DOS) else 1)[0]
        result["fn_created"]  = best["fn_created"]
        result["fn_modified"] = best["fn_modified"]
        result["fn_name"]     = best["fn_name"]
    return result


class MftCorroborator:
    """
    Opened once at monitor start.  Provides:
      - read_mft_record(file_ref)  → raw bytes for a specific file
      - current_lsn()             → current $LogFile LSN (proxy for "now" in LSN space)
      - corroborate(file_ref, fname, now) → extra evidence dict or None
    """
    def __init__(self, drive):
        self.drive   = drive[0].upper()
        self.k32     = ctypes.windll.kernel32
        self.handle  = None
        self.bps     = 512          # bytes per sector
        self.bpc     = 4096         # bytes per cluster
        self.mft_rec = 1024         # bytes per MFT record
        self.mft_off = 0            # byte offset of first MFT record on volume
        self._logfile_lsn_cache = 0
        self._lsn_cache_time    = 0

    def open(self):
        h = self.k32.CreateFileW(
            "\\\\.\\%s:" % self.drive,
            GENERIC_READ,
            FILE_SHARE_ALL,
            None, OPEN_EXISTING,
            FILE_FLAG_NO_BUFFERING | FILE_FLAG_RANDOM_ACCESS,
            None
        )
        if h == ctypes.wintypes.HANDLE(-1).value:
            return False
        self.handle = h
        # Get NTFS geometry
        vd  = NTFS_VOLUME_DATA()
        ret = ctypes.wintypes.DWORD(0)
        if self.k32.DeviceIoControl(h, FSCTL_GET_NTFS_VOLUME_DATA,
                                     None, 0, ctypes.byref(vd), ctypes.sizeof(vd),
                                     ctypes.byref(ret), None):
            self.bps     = vd.BytesPerSector
            self.bpc     = vd.BytesPerCluster
            self.mft_rec = vd.BytesPerFileRecordSegment
            self.mft_off = vd.MftStartLcn * vd.BytesPerCluster
        return True

    def close(self):
        if self.handle:
            self.k32.CloseHandle(self.handle)
            self.handle = None

    def _read_raw(self, offset, length):
        if not self.handle:
            return None
        aligned = (offset // self.bps) * self.bps
        skip    = offset - aligned
        rlen    = ((skip + length + self.bps - 1) // self.bps) * self.bps
        lo = aligned & 0xFFFFFFFF
        hi = ctypes.c_long(aligned >> 32)
        if self.k32.SetFilePointer(self.handle, lo, ctypes.byref(hi), 0) == 0xFFFFFFFF:
            return None
        buf = ctypes.create_string_buffer(rlen)
        br  = ctypes.wintypes.DWORD(0)
        if not self.k32.ReadFile(self.handle, buf, rlen, ctypes.byref(br), None):
            return None
        return buf.raw[skip:skip+length]

    def read_mft_record(self, file_ref):
        """Read the MFT record for a given file reference number."""
        try:
            off = self.mft_off + int(file_ref) * self.mft_rec
            return self._read_raw(off, self.mft_rec)
        except Exception:
            return None

    def current_lsn(self):
        """Return current $LogFile LSN (cached for 10 seconds)."""
        now = time.time()
        if now - self._lsn_cache_time < 10:
            return self._logfile_lsn_cache
        try:
            raw = self._read_raw(self.mft_off + 2 * self.mft_rec, self.mft_rec)
            if raw and raw[:4] == b'FILE':
                lsn = abs(struct.unpack_from("<q", raw, 8)[0])
                self._logfile_lsn_cache = lsn
                self._lsn_cache_time    = now
                return lsn
        except Exception:
            pass
        return self._logfile_lsn_cache

    def corroborate(self, file_ref, fname, now):
        """
        Read the file's MFT record and cross-reference with USN observation.
        Returns a dict with extra evidence fields, or None if unavailable.

        Returns:
          si_modified  — what $SI says (attacker-controlled)
          fn_modified  — what $FN says (kernel-controlled, tamper-proof)
          fn_created   — $FN creation (kernel-written at file arrival)
          lsn          — MFT record LSN (recent = record was written recently)
          current_lsn  — current $LogFile LSN (baseline for "now")
          lsn_age_pct  — how recent this LSN is (100% = just written)
          si_fn_gap_days — days between $SI and $FN modified (0 = legitimate)
          proof_level  — "CONFIRMED", "STRONG", "WEAK", "INCONCLUSIVE"
        """
        try:
            raw = self.read_mft_record(file_ref)
            if raw is None:
                return None
            rec = parse_mft_record_quick(raw)
            if rec is None:
                return None

            cur_lsn   = self.current_lsn()
            file_lsn  = rec["lsn"]
            si_mod    = rec["si_modified"]
            fn_mod    = rec["fn_modified"]
            fn_cre    = rec["fn_created"]

            # LSN age: what fraction of the current LSN is this file's LSN?
            lsn_age_pct = (file_lsn / cur_lsn * 100) if cur_lsn > 0 else 0

            # $SI vs $FN gap
            si_fn_gap = None
            if si_mod and fn_mod:
                si_fn_gap = abs((si_mod - fn_mod).days)

            # How old does $SI claim the file is?
            si_age_days = (now - si_mod).days if si_mod else None

            # Determine proof level
            proof = "INCONCLUSIVE"
            if si_fn_gap is not None and si_fn_gap > 1:
                if lsn_age_pct > 90 and si_age_days and si_age_days > 30:
                    proof = "CONFIRMED"    # LSN says just written + $SI/$FN mismatch
                elif si_fn_gap > 30:
                    proof = "STRONG"       # big $SI/$FN gap even without LSN
                else:
                    proof = "WEAK"
            elif lsn_age_pct > 95 and si_age_days and si_age_days > 180:
                proof = "STRONG"           # LSN very recent, timestamp very old

            return {
                "si_modified":    si_mod.strftime("%Y-%m-%d %H:%M:%S UTC") if si_mod else "N/A",
                "fn_modified":    fn_mod.strftime("%Y-%m-%d %H:%M:%S UTC") if fn_mod else "N/A",
                "fn_created":     fn_cre.strftime("%Y-%m-%d %H:%M:%S UTC") if fn_cre else "N/A",
                "lsn":            hex(file_lsn),
                "current_lsn":    hex(cur_lsn),
                "lsn_age_pct":    round(lsn_age_pct, 1),
                "si_fn_gap_days": si_fn_gap,
                "proof_level":    proof,
            }
        except Exception:
            return None


def dt_str(dt):
    if dt is None: return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S UTC")


def filetime_to_dt(ft):

    """Convert a FILETIME struct to a UTC datetime."""
    ticks = (ft.dwHighDateTime << 32) | ft.dwLowDateTime
    if ticks == 0:
        return None
    return WINDOWS_EPOCH + datetime.timedelta(microseconds=ticks // 10)

def get_file_times(path):
    """
    Open the file and read its actual NTFS timestamps via
    GetFileInformationByHandle. Returns (created_dt, last_write_dt) or (None, None).
    This is independent of Python's os.stat() which can be spoofed by some tools.
    """
    k32 = ctypes.windll.kernel32
    FILE_SHARE_ALL = 0x7
    h = k32.CreateFileW(
        path,
        0x80000000,        # GENERIC_READ
        FILE_SHARE_ALL,
        None,
        3,                 # OPEN_EXISTING
        0x02000000,        # FILE_FLAG_BACKUP_SEMANTICS
        None
    )
    if h == ctypes.wintypes.HANDLE(-1).value:
        return None, None
    try:
        info = BY_HANDLE_FILE_INFORMATION()
        if k32.GetFileInformationByHandle(h, ctypes.byref(info)):
            return filetime_to_dt(info.ftCreationTime), filetime_to_dt(info.ftLastWriteTime)
    finally:
        k32.CloseHandle(h)
    return None, None


# ── Office file analysis (ported from detector__9_.py) ──────────────────────

import zipfile as _zipfile
import xml.etree.ElementTree as _ET

OFFICE_EXTENSIONS = {'.xlsx', '.docx', '.pptx', '.xlsm', '.docm', '.pptm', '.odt', '.ods'}

_XML_NS = {
    'dc':      'http://purl.org/dc/elements/1.1/',
    'cp':      'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
    'dcterms': 'http://purl.org/dc/terms/',
}

# Blank template names — these are NOT suspicious even if internal date looks old
TEMPLATE_SIGNALS = [
    "new microsoft excel", "new microsoft word", "new microsoft powerpoint",
    "book1", "sheet1", "document1", "presentation1",
    "new workbook", "workbook1",
]

# Lazy-loaded once at first Office file check
_LOCAL_OFFICE_AUTHORS = None

def _get_local_office_authors():
    """
    Read registered Office username from Windows registry.
    Returns set of lowercase names so we can suppress false positives
    on files created by the current user on this machine.
    """
    names = set()
    try:
        import winreg
        for hive, path in [
            (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Office\Common\UserInfo"),
            (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Office\Common\UserInfo"),
        ]:
            try:
                key = winreg.OpenKey(hive, path)
                for val in ("UserName", "RegsiteredOrganization"):
                    try:
                        v, _ = winreg.QueryValueEx(key, val)
                        if v and v.strip():
                            names.add(v.strip().lower())
                    except: pass
                winreg.CloseKey(key)
            except: pass
    except ImportError:
        pass
    names.add(os.environ.get("USERNAME", "").lower())
    names.add(os.environ.get("COMPUTERNAME", "").lower())
    names.discard("")
    return names

def _is_local_author(author_name):
    global _LOCAL_OFFICE_AUTHORS
    if _LOCAL_OFFICE_AUTHORS is None:
        _LOCAL_OFFICE_AUTHORS = _get_local_office_authors()
    if not author_name:
        return False
    return author_name.strip().lower() in _LOCAL_OFFICE_AUTHORS

def _parse_iso(s):
    if not s: return None
    try: return datetime.datetime.fromisoformat(s.replace("Z", "+00:00"))
    except: return None

def _is_blank_template(filepath, meta, file_size):
    """
    Returns True if file is clearly a blank Office template.
    Requires multiple signals — never suppresses on a single signal alone,
    EXCEPT for well-known generic template names which are always safe to skip.
    """
    fname = os.path.basename(filepath).lower()
    # Hard rule: generic template name is enough on its own
    if any(t in fname for t in TEMPLATE_SIGNALS):
        return True
    # Soft rule: need ALL THREE — tiny file + low revision + no author
    is_tiny    = file_size < 15000
    is_low_rev = False
    try:
        is_low_rev = int(meta.get("revision", "99")) <= 2
    except: pass
    has_no_author = not meta.get("original_author", "").strip()
    return is_tiny and is_low_rev and has_no_author

def _extract_office_metadata(filepath):
    """Extract internal creation/author metadata from Office Open XML files."""
    try:
        with _zipfile.ZipFile(filepath) as z:
            if "docProps/core.xml" not in z.namelist():
                return None
            root = _ET.fromstring(z.read("docProps/core.xml"))
        def get(tag, ns):
            el = root.find(f"{ns}:{tag}", _XML_NS)
            return el.text if el is not None else None
        return {
            "original_author":   get("creator",        "dc"),
            "last_modified_by":  get("lastModifiedBy", "cp"),
            "internal_created":  get("created",        "dcterms"),
            "internal_modified": get("modified",       "dcterms"),
            "revision":          get("revision",       "cp"),
        }
    except: return None

def analyze_office_file_live(file_path, ntfs_created_dt, ntfs_modified_dt):
    """
    Full 4-check Office metadata analysis for live detection.
    Ported directly from detector__9_.py analyze_office_file().

    Parameters:
      file_path       — full path to the file on disk
      ntfs_created_dt — datetime when file arrived on this volume ($FN created)
      ntfs_modified_dt— datetime of file's own LastWriteTime ($SI modified)

    Returns dict with keys:
      suspicious      — bool, True if any anomaly found with confidence >= 20
      confidence      — float 0-100
      severity        — "CRITICAL" / "HIGH" / "MEDIUM"
      anomalies       — list of anomaly type strings
      details         — list of human-readable detail strings
      original_author — str or None
      last_modified_by— str or None
      internal_created— str or None
      internal_modified—str or None
      is_local        — bool, True if authored by local user
    Returns None if not an Office file, blank template, or no anomalies.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in OFFICE_EXTENSIONS:
        return None

    # Get file size for template check
    try:
        file_size = os.path.getsize(file_path)
    except:
        return None

    meta = _extract_office_metadata(file_path)
    if not meta:
        return None

    # Suppress blank templates — this was the root cause of the xlsx false positive
    if _is_blank_template(file_path, meta, file_size):
        return None

    int_created  = _parse_iso(meta.get("internal_created"))
    int_modified = _parse_iso(meta.get("internal_modified"))
    author       = meta.get("original_author", "") or ""
    last_by      = meta.get("last_modified_by", "") or ""

    ntfs_created  = ntfs_created_dt
    ntfs_modified = ntfs_modified_dt

    anomalies  = []
    details    = []
    confidence = 0.0

    # Check 1: NTFS modified < NTFS created (impossible — copied file signature)
    if ntfs_modified and ntfs_created:
        if ntfs_modified < ntfs_created - datetime.timedelta(seconds=5):
            diff_min = int((ntfs_created - ntfs_modified).total_seconds() / 60)
            anomalies.append("MODIFIED_BEFORE_CREATED")
            details.append(
                f"NTFS modified ({ntfs_modified.strftime('%Y-%m-%d %H:%M UTC')}) is "
                f"{diff_min} min BEFORE NTFS created ({ntfs_created.strftime('%Y-%m-%d %H:%M UTC')}) "
                f"— strong indicator file was copied from another system"
            )
            confidence += 45

    # Check 2: Internal metadata predates NTFS creation (different origin system)
    # Only flag if author is NOT the local machine's Office user
    if int_created and ntfs_created:
        diff_days = (ntfs_created - int_created).days
        if diff_days > 1 and not _is_local_author(author):
            anomalies.append("COPIED_FROM_ANOTHER_SYSTEM")
            details.append(
                f"Internally created {diff_days} days ago "
                f"({int_created.strftime('%Y-%m-%d %H:%M UTC')}) on a DIFFERENT machine, "
                f"but first appeared here on {ntfs_created.strftime('%Y-%m-%d %H:%M UTC')}"
            )
            confidence += 60 if diff_days > 30 else 40

    # Check 3: Internal modified vs NTFS modified mismatch
    if int_modified and ntfs_modified:
        diff_days = abs((ntfs_modified - int_modified).days)
        if diff_days > 1 and not _is_local_author(author):
            anomalies.append("INTERNAL_NTFS_MISMATCH")
            details.append(
                f"Internal modified ({int_modified.strftime('%Y-%m-%d')}) differs from "
                f"NTFS modified ({ntfs_modified.strftime('%Y-%m-%d')}) by {diff_days} days"
            )
            confidence += 25

    # Check 4: Author from a different machine
    if author and not _is_local_author(author):
        anomalies.append("AUTHOR_IDENTIFIED")
        details.append(f"Originally authored by '{author}' — NOT registered on this machine")
        confidence += 15
    elif author and _is_local_author(author):
        # Local user authored it — heavily downgrade to avoid false positives
        confidence = min(confidence, 30)

    if not anomalies or confidence < 20:
        return None

    confidence = min(confidence, 100.0)
    sev = "CRITICAL" if confidence >= 75 else "HIGH" if confidence >= 50 else "MEDIUM"

    return {
        "suspicious":        True,
        "confidence":        round(confidence, 1),
        "severity":          sev,
        "anomalies":         anomalies,
        "details":           details,
        "original_author":   author or None,
        "last_modified_by":  last_by or None,
        "internal_created":  meta.get("internal_created"),
        "internal_modified": meta.get("internal_modified"),
        "is_local":          _is_local_author(author),
    }


def read_office_origin(file_path):
    """Legacy shim — used in places that just need raw metadata dict."""
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in OFFICE_EXTENSIONS:
        return None
    return _extract_office_metadata(file_path)


def classify_copy(st, fname, drive, now_real):
    """
    Detects file copies via two USN signatures:

    A) Separate records:  FILE_CREATE → DATA_EXTEND → CLOSE
    B) Combined record:   FILE_CREATE|DATA_EXTEND   → CLOSE  (Explorer drag-copy)

    No BASIC_INFO_CHANGE = plain copy (not a timestomp, already caught by D1/D2).
    Opens the file afterwards to compare its own LastWriteTime vs arrival time.
    """
    has_create = 0x100 in st.reasons_seen
    has_data   = bool(st.reasons_seen & {0x1, 0x2, 0x4})
    has_meta   = 0x8000 in st.reasons_seen
    has_close  = st.close_seen

    if not (has_create and has_data and has_close):
        return None
    if has_meta:
        return None   # timestomp detections already handle this
    if st.alerted_copy:
        return None

    file_path = f"{drive}:\\{fname}"
    created_dt, last_write_dt = get_file_times(file_path)
    arrival_time = st.created_at or now_real

    if last_write_dt and last_write_dt < arrival_time:
        age_days = (arrival_time - last_write_dt).days
        if age_days > 1:
            return (
                "FILE_COPIED_FROM_ELSEWHERE",
                "HIGH",
                (f"'{fname}' COPIED onto {drive}:\\ — LastWriteTime is "
                 f"{age_days} days old ({last_write_dt.strftime('%Y-%m-%d %H:%M')} UTC) "
                 f"but file just arrived. Originated on another system or drive.")
            )

    created_str = created_dt.strftime('%Y-%m-%d %H:%M:%S UTC') if created_dt else "unknown"
    return (
        "FILE_COPIED_TO_DRIVE",
        "HIGH",
        (f"'{fname}' COPIED onto {drive}:\\ "
         f"(FILE_CREATE + DATA_EXTEND + CLOSE, no timestamp manipulation). "
         f"NTFS created: {created_str}.")
    )


# ── Main Monitor ──────────────────────────────────────────────────────────────
def monitor_live(drive="C", output_file=None, poll_interval=0.3):
    d   = drive[0].upper()
    k32 = ctypes.windll.kernel32

    print_banner(d)
    print(f"[*] Opening volume {d}:\\ ...", flush=True)

    h = k32.CreateFileW(
        f"\\\\.\\{d}:",
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None, OPEN_EXISTING, 0, None
    )
    if h == ctypes.wintypes.HANDLE(-1).value:
        print(f"{RED}[!] Cannot open {d}: — Run as Administrator! Error: {k32.GetLastError()}{RST}")
        sys.exit(1)
    print(f"[+] Volume opened OK")

    # Open MFT corroborator — second handle for raw MFT/LogFile reads
    mft = MftCorroborator(d)
    if mft.open():
        print(f"[+] MFT corroborator ready  (LSN baseline: 0x{mft.current_lsn():X})")
        print(f"[+] Mode: USN Journal + $LogFile LSN + MFT $FN cross-reference")
    else:
        print(f"{YELLOW}[!] MFT corroborator unavailable — USN-only detection mode{RST}")
        mft = None

    jd = USN_JOURNAL_DATA(); br = ctypes.wintypes.DWORD(0)
    if not k32.DeviceIoControl(h, FSCTL_QUERY_USN_JOURNAL,
                                None, 0, ctypes.byref(jd), ctypes.sizeof(jd),
                                ctypes.byref(br), None):
        print(f"[!] Query journal failed: {k32.GetLastError()}"); k32.CloseHandle(h); return

    cur = jd.NextUsn
    print(f"[+] Journal ID : {jd.UsnJournalID}")
    print(f"[+] Starting at USN: {cur:,}")
    print(f"\n{GREEN}[*] Monitoring for live timestamp tampering + file copies...{RST}")
    print(DIM + "    Watching for: timestomp, drop-and-stomp, stomp-and-rename, file copies" + RST)
    print(DIM + f"    Output: {output_file or 'console only'}" + RST)
    print(f"\n{DIM}{'─'*65}{RST}\n")

    buf            = ctypes.create_string_buffer(65536)
    states         = defaultdict(FileState)
    alerts         = []
    alert_dedup    = {}   # key -> last fired time, to suppress duplicates within 10s
    events         = 0
    first_seen_time = {}
    monitor_start  = datetime.datetime.now(datetime.timezone.utc)

    try:
        while True:
            rd = READ_USN_DATA()
            rd.StartUsn=cur; rd.ReasonMask=0xFFFFFFFF
            rd.ReturnOnlyOnClose=0; rd.Timeout=0
            rd.BytesToWaitFor=0; rd.UsnJournalID=jd.UsnJournalID

            ret = ctypes.wintypes.DWORD(0)
            ok  = k32.DeviceIoControl(h, FSCTL_READ_USN_JOURNAL,
                                       ctypes.byref(rd), ctypes.sizeof(rd),
                                       buf, 65536, ctypes.byref(ret), None)

            if not ok:
                err = k32.GetLastError()
                if err in (38, 259):
                    print(f"\r  {DIM}[{datetime.datetime.now().strftime('%H:%M:%S')}] "
                          f"Monitoring... events:{events}  alerts:{len(alerts)}{RST}",
                          end="", flush=True)
                    time.sleep(poll_interval)
                    continue
                time.sleep(poll_interval); continue

            raw = buf.raw[:ret.value]
            if len(raw) < 8: time.sleep(poll_interval); continue

            new_usn = struct.unpack_from("<q", raw, 0)[0]
            if new_usn <= cur: time.sleep(poll_interval); continue
            cur = new_usn

            off = 8
            while off < len(raw) - 60:
                try:
                    rl  = struct.unpack_from("<I", raw, off)[0]
                    mv  = struct.unpack_from("<H", raw, off+4)[0]
                    if rl < 60 or mv not in (2, 3): break
                    if off + rl > len(raw): break

                    fref = str(struct.unpack_from("<Q", raw, off+8)[0] & 0xFFFFFFFFFFFF)
                    usn  = struct.unpack_from("<Q", raw, off+24)[0]
                    tft  = struct.unpack_from("<Q", raw, off+32)[0]
                    rsn  = struct.unpack_from("<I", raw, off+40)[0]
                    fnl  = struct.unpack_from("<H", raw, off+56)[0]
                    fno  = struct.unpack_from("<H", raw, off+58)[0]

                    try:    fname = raw[off+fno:off+fno+fnl].decode("utf-16-le")
                    except: fname = "<unknown>"

                    usn_time = (WINDOWS_EPOCH + datetime.timedelta(microseconds=tft//10)) if tft else None
                    now_real = datetime.datetime.now(datetime.timezone.utc)
                    events  += 1

                    if is_noisy(fname):
                        off += rl; continue

                    st = states[fref]
                    st.history.append((now_real, rsn, fname))
                    if len(st.history) > 20: st.history = st.history[-20:]

                    # Accumulate all reason flags seen for this file ref
                    st.reasons_seen.add(rsn)
                    for flag in REASONS:
                        if rsn & flag:
                            st.reasons_seen.add(flag)

                    has_data       = bool(rsn & 0x7)
                    has_meta       = bool(rsn & 0x8000)
                    is_create      = bool(rsn & 0x100)
                    is_close       = bool(rsn & 0x80000000)
                    is_delete      = bool(rsn & 0x200)
                    is_rename_old  = bool(rsn & 0x1000)
                    is_rename_new  = bool(rsn & 0x2000)

                    # Track most recent filename for this ref (rename tracking)
                    if fname and fname != "<unknown>":
                        st.last_fname = fname

                    if is_create:
                        # Reset state for this file ref on new creation
                        st.created_at      = now_real
                        st.last_data_write = None
                        st.reasons_seen    = {0x100}
                        st.close_seen      = False
                        st.alerted_copy    = False
                        st.alerted_delete  = False
                        st.rename_old_time = None
                        st.rename_old_name = None
                        first_seen_time[fref] = now_real

                    if has_data:
                        st.last_data_write = now_real

                    if is_close:
                        st.close_seen = True

                    if is_rename_old:
                        # Record the old name and time — if no RENAME_NEW arrives
                        # within ~5s on the same volume it means file left the drive
                        st.rename_old_time = now_real
                        st.rename_old_name = fname

                    alert = None

                    # ══════════════════════════════════════════════════════════
                    # DETECTION LOGIC
                    #
                    # Real USN copy signature (confirmed via usn_debug.py):
                    #   FILE_CREATE | EA_CHANGE
                    #   FILE_CREATE | EA_CHANGE | SECURITY_CHANGE
                    #   DATA_EXTEND | FILE_CREATE | EA_CHANGE | SECURITY_CHANGE
                    #   DATA_OVERWRITE | DATA_EXTEND | FILE_CREATE | ... | BASIC_INFO_CHANGE
                    #   DATA_OVERWRITE | DATA_EXTEND | FILE_CREATE | ... | BASIC_INFO_CHANGE | CLOSE
                    #
                    # Key insight: copies ALWAYS have BOTH has_data AND has_meta
                    # together with has_create. Pure timestomps have has_meta
                    # WITHOUT has_data. That's the distinguishing flag.
                    # ══════════════════════════════════════════════════════════

                    # ── Detection 1: Pure timestamp manipulation ───────────────
                    # BASIC_INFO_CHANGE with NO data write = someone only touched
                    # the timestamp. Classic timestomp.
                    #
                    # FALSE POSITIVE GUARD:
                    # Explorer emits a stray BASIC_INFO_CHANGE when you rename a
                    # file (touches last-access/metadata). Excel also fires one
                    # when closing a saved file. These are legitimate operations.
                    # Guard: if MFT is available, only fire when $SI vs $FN gap
                    # is > 1 day (proves the timestamp was actually rolled back).
                    # If MFT unavailable, fire always (better to over-alert).
                    if has_meta and not has_data and not is_create:
                        corr = mft.corroborate(fref, fname, now_real) if mft else None

                        # MFT available — use it as gatekeeper
                        if corr is not None:
                            gap_days = corr["si_fn_gap_days"] or 0
                            if gap_days < 2:
                                # Gap is tiny → normal app/Explorer metadata touch → suppress
                                pass
                            else:
                                # Real gap → $SI was rolled back
                                file_age_str = ""
                                if fref in first_seen_time:
                                    fa = (now_real - first_seen_time[fref]).total_seconds()
                                    file_age_str = f" File first seen {fa:.0f}s ago."
                                proof = corr["proof_level"]
                                extra_detail = ""
                                if proof in ("CONFIRMED", "STRONG"):
                                    extra_detail = (
                                        f" [$FN PROOF: $SI={corr['si_modified']} vs "
                                        f"$FN={corr['fn_modified']} ({gap_days}d gap). "
                                        f"LSN 0x{corr['lsn'][2:].upper()} is {corr['lsn_age_pct']}% "
                                        f"of current journal. Proof: {proof}]"
                                    )
                                atype = "TIMESTOMP_MFT_CONFIRMED" if proof == "CONFIRMED" else "LIVE_TIMESTOMP_DETECTED"
                                alert = {
                                    "time":       now_real.isoformat(),
                                    "severity":   "CRITICAL",
                                    "alert_type": atype,
                                    "file_name":  fname,
                                    "file_ref":   fref,
                                    "detail":     (f"'{fname}' had ONLY its timestamp changed "
                                                   f"(BASIC_INFO_CHANGE, no data written).{file_age_str}"
                                                   f"{extra_detail}"),
                                    "claimed_ts": corr["si_modified"],
                                    "actual_ts":  corr["fn_modified"],
                                    "mft_proof":  corr,
                                }
                        else:
                            # MFT unavailable — apply filename-based guards before firing.
                            # If the file was JUST created this session (fref in first_seen_time)
                            # AND its name looks like a blank Office template, suppress it.
                            # This catches the "New Microsoft Excel Worksheet.xlsx" case where
                            # Excel fires BASIC_INFO_CHANGE right after creating the file and
                            # the MFT corroborator can't yet read the record.
                            fname_lower = fname.lower()
                            is_template_name = any(t in fname_lower for t in TEMPLATE_SIGNALS)
                            is_new_this_session = fref in first_seen_time

                            if is_template_name and is_new_this_session:
                                pass  # blank template just created → suppress
                            else:
                                # Also suppress if file was created very recently this session
                                # (< 30s) — MFT just hasn't caught up yet, not a real stomp
                                suppress = False
                                if is_new_this_session:
                                    age_s = (now_real - first_seen_time[fref]).total_seconds()
                                    if age_s < 30:
                                        suppress = True

                                if not suppress:
                                    file_age_str = ""
                                    if is_new_this_session:
                                        fa = (now_real - first_seen_time[fref]).total_seconds()
                                        file_age_str = f" File first seen {fa:.0f}s ago."
                                    alert = {
                                        "time":       now_real.isoformat(),
                                        "severity":   "CRITICAL",
                                        "alert_type": "LIVE_TIMESTOMP_DETECTED",
                                        "file_name":  fname,
                                        "file_ref":   fref,
                                        "detail":     (f"'{fname}' had ONLY its timestamp changed "
                                                       f"(BASIC_INFO_CHANGE, no data written).{file_age_str}"),
                                        "claimed_ts": None,
                                        "actual_ts":  now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                        "mft_proof":  None,
                                    }

                    # ── Detection 2: Drop and timestomp ───────────────────────
                    # File written then BASIC_INFO_CHANGE fires separately (no data).
                    #
                    # FALSE POSITIVE GUARD — Excel/Word save pattern:
                    # When Excel saves a file it writes DATA then immediately fires
                    # BASIC_INFO_CHANGE in the same flush (gap = 0.0s). This is
                    # indistinguishable from a real timestomp by timing alone.
                    #
                    # Two-stage guard:
                    #  1. Require gap >= 1s (Excel fires at 0.0s, attackers need
                    #     a separate PowerShell command so gap is always > 1s)
                    #  2. If MFT available, require si_fn_gap_days > 1 — a legit
                    #     Excel save has $SI ≈ $FN (gap 0), a real timestomp has
                    #     $SI rolled back years. MFT kills the false positive cleanly.
                    if has_meta and not has_data and not is_create and st.last_data_write:
                        gap = (now_real - st.last_data_write).total_seconds()
                        if gap >= 1.0 and gap < 60:
                            corr2 = mft.corroborate(fref, fname, now_real) if mft else None

                            # MFT available — require confirmed $SI rollback
                            if corr2 is not None:
                                mft_gap = corr2["si_fn_gap_days"] or 0
                                if mft_gap < 2:
                                    pass  # $SI matches $FN → legitimate app save → suppress
                                else:
                                    corr2_detail = (
                                        f" [$FN CONFIRMS: $SI={corr2['si_modified']} "
                                        f"vs $FN={corr2['fn_modified']} — "
                                        f"{mft_gap}d gap. "
                                        f"LSN {corr2['lsn']} ({corr2['lsn_age_pct']}% of journal). "
                                        f"Proof: {corr2['proof_level']}]"
                                    )
                                    alert = {
                                        "time":       now_real.isoformat(),
                                        "severity":   "CRITICAL",
                                        "alert_type": "DROP_AND_TIMESTOMP",
                                        "file_name":  fname,
                                        "file_ref":   fref,
                                        "detail":     (f"'{fname}' written {gap:.1f}s ago then "
                                                       f"ONLY timestamp changed — drop-and-stomp."
                                                       f"{corr2_detail}"),
                                        "claimed_ts": corr2["si_modified"],
                                        "actual_ts":  corr2["fn_modified"],
                                        "mft_proof":  corr2,
                                    }
                            else:
                                # No MFT — fire on gap >= 1s (timing heuristic only)
                                alert = {
                                    "time":       now_real.isoformat(),
                                    "severity":   "CRITICAL",
                                    "alert_type": "DROP_AND_TIMESTOMP",
                                    "file_name":  fname,
                                    "file_ref":   fref,
                                    "detail":     (f"'{fname}' written {gap:.1f}s ago then "
                                                   f"ONLY timestamp changed — drop-and-stomp pattern."),
                                    "claimed_ts": None,
                                    "actual_ts":  now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                    "mft_proof":  None,
                                }

                    # ── Detection 3: Rename after CONFIRMED timestomp ──────────
                    # Fires when a file is renamed after its timestamp was provably
                    # rolled back. Requires MFT proof (si_fn_gap > 30 days) OR,
                    # if MFT unavailable, a deliberate delay (>60s) between the
                    # BASIC_INFO_CHANGE and the rename — ruling out Explorer/app
                    # atomic saves which rename within milliseconds.
                    #
                    # FALSE POSITIVE GUARD:
                    # When you rename a newly created file in Explorer, Windows
                    # emits BASIC_INFO_CHANGE + RENAME_NEW_NAME in rapid succession.
                    # The old 3s threshold was too short. We now require:
                    #   - MFT available: gap_days > 30 (hard proof)
                    #   - MFT unavailable: stomp happened > 60s before rename
                    #     AND file existed before this monitoring session
                    #     (first_seen_time not set = pre-existing file)
                    if rsn & 0x2000:  # RENAME_NEW_NAME
                        recent_stomp = [r for _,r,_ in st.history[-8:]
                                        if (r & 0x8000) and not (r & 0x7)]
                        if recent_stomp:
                            corr3 = mft.corroborate(fref, fname, now_real) if mft else None
                            si_actually_old = False
                            si_age_days     = 0
                            corr3_detail    = ""

                            if corr3 is not None:
                                # MFT available — require hard gap > 30 days
                                gap = corr3["si_fn_gap_days"] or 0
                                if gap > 30:
                                    si_actually_old = True
                                    si_age_days     = gap
                                    corr3_detail    = (
                                        f" [$FN PROOF: $SI={corr3['si_modified']} vs "
                                        f"$FN={corr3['fn_modified']}, gap={si_age_days}d, "
                                        f"proof={corr3['proof_level']}]"
                                    )
                                # else: gap is tiny → Explorer/app touch → suppress
                            else:
                                # No MFT — require >60s AND file pre-existed this session
                                file_is_new = fref in first_seen_time
                                stomp_times = [t for t,r,_ in st.history[-8:]
                                               if (r & 0x8000) and not (r & 0x7)]
                                if stomp_times and not file_is_new:
                                    elapsed = (now_real - stomp_times[-1]).total_seconds()
                                    if elapsed > 60:
                                        si_actually_old = True
                                        si_age_days     = 0

                            if si_actually_old:
                                alert = {
                                    "time":       now_real.isoformat(),
                                    "severity":   "CRITICAL",
                                    "alert_type": "TIMESTOMP_THEN_RENAME",
                                    "file_name":  fname,
                                    "file_ref":   fref,
                                    "detail":     (
                                        f"'{fname}' renamed after timestamp was rolled back "
                                        f"{si_age_days}+ days — attacker hiding a timestomped file."
                                        f"{corr3_detail}"
                                    ),
                                    "claimed_ts": corr3["si_modified"] if corr3 else None,
                                    "actual_ts":  corr3["fn_modified"] if corr3 else now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                    "mft_proof":  corr3,
                                }
                            # gap is small → Explorer/app atomic save → suppress silently

                    # ── Detection 4: File copy ─────────────────────────────────
                    # Real copy signature: FILE_CREATE + DATA + BASIC_INFO_CHANGE
                    # all present together (Windows preserves source timestamps).
                    #
                    # Two-stage decision:
                    #  Stage 1 (NTFS age check): suppress if last_write_dt < 2 days
                    #    old — this eliminates Excel/Word new file, browser saves, etc.
                    #  Stage 2 (Office analysis): run full 4-check analysis from
                    #    detector__9_.py including template detection, local author
                    #    check, internal vs NTFS date comparison, confidence scoring.
                    #    The blank template check here is the definitive fix for the
                    #    "New Microsoft Excel Worksheet.xlsx" false positive.
                    if is_close and is_create and has_data and has_meta and not st.alerted_copy:
                        file_path    = f"{d}:\\{fname}"
                        created_dt, last_write_dt = get_file_times(file_path)
                        arrival      = st.created_at or now_real

                        age_days = 0
                        if last_write_dt and last_write_dt < arrival:
                            age_days = (arrival - last_write_dt).days

                        if age_days < 2:
                            # Timestamps current → locally created → suppress entirely
                            st.alerted_copy = True
                        else:
                            # File has old $SI → could be a copy from another machine

                            # Run full Office analysis (detector__9_.py logic)
                            # This will return None for blank templates, local-user files, etc.
                            office_result = analyze_office_file_live(
                                file_path,
                                ntfs_created_dt  = arrival,
                                ntfs_modified_dt = last_write_dt,
                            )

                            # MFT corroboration
                            corr4        = mft.corroborate(fref, fname, now_real) if mft else None
                            corr4_detail = ""
                            if corr4 and corr4["si_fn_gap_days"] and corr4["si_fn_gap_days"] > 1:
                                corr4_detail = (
                                    f" [$FN PROOF: $SI={corr4['si_modified']} vs "
                                    f"$FN created={corr4['fn_created']} — "
                                    f"{corr4['si_fn_gap_days']}d gap, "
                                    f"proof={corr4['proof_level']}]"
                                )

                            # Build detail string
                            base_detail = (
                                f"'{fname}' COPIED onto {d}:\\ — "
                                f"LastWriteTime is {age_days} days old "
                                f"({last_write_dt.strftime('%Y-%m-%d %H:%M')} UTC) "
                                f"but arrived just now. Came from another machine/drive."
                                f"{corr4_detail}"
                            )

                            # Append Office-specific findings if present
                            office_detail = ""
                            if office_result:
                                for d_line in office_result["details"]:
                                    office_detail += f" | {d_line}"
                                # Escalate severity if Office analysis confirmed it
                                if office_result["confidence"] >= 75:
                                    sev = "CRITICAL"
                                elif office_result["confidence"] >= 50:
                                    sev = "HIGH"
                                else:
                                    sev = "HIGH"
                            else:
                                sev = "HIGH"

                            alert = {
                                "time":          now_real.isoformat(),
                                "severity":      sev,
                                "alert_type":    "FILE_COPIED_FROM_ELSEWHERE",
                                "file_name":     fname,
                                "file_ref":      fref,
                                "detail":        base_detail + office_detail,
                                "claimed_ts":    last_write_dt.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                "actual_ts":     now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                "office_origin": office_result,
                                "mft_proof":     corr4,
                            }
                            st.alerted_copy = True

                    # ── Detection 5: File deleted ──────────────────────────────
                    # FILE_DELETE on the monitored drive. Flags when a file is
                    # deleted — especially valuable if it was recently created or
                    # timestomped (attacker covering tracks).
                    #
                    # Context-aware severity:
                    #   CRITICAL — file was timestomped then deleted (evidence wipe)
                    #   HIGH     — file was created this session then deleted
                    #   MEDIUM   — pre-existing file deleted
                    #
                    # False positive guard: skip Recycle Bin and common temp patterns
                    # (already handled by is_noisy, but we add $Recycle.Bin check).
                    if is_delete and not st.alerted_delete:
                        skip_delete = "$recycle" in fname.lower() or "~$" in fname.lower()
                        if not skip_delete:
                            was_stomped = any(
                                (r & 0x8000) and not (r & 0x7)
                                for _, r, _ in st.history[-10:]
                            )
                            was_created_this_session = fref in first_seen_time

                            if was_stomped:
                                sev     = "CRITICAL"
                                atype   = "TIMESTOMPED_FILE_DELETED"
                                detail  = (
                                    f"'{fname}' was DELETED after its timestamp was manipulated "
                                    f"— attacker wiping evidence of a timestomped file."
                                )
                            elif was_created_this_session:
                                age_s   = (now_real - first_seen_time[fref]).total_seconds()
                                sev     = "HIGH"
                                atype   = "FILE_DELETED"
                                detail  = (
                                    f"'{fname}' was DELETED {age_s:.0f}s after arriving on {d}:\\ "
                                    f"— possible tool cleanup or evidence removal."
                                )
                            else:
                                sev     = "MEDIUM"
                                atype   = "FILE_DELETED"
                                detail  = f"{fname} was DELETED from {d}:\\"

                            alert = {
                                "time":       now_real.isoformat(),
                                "severity":   sev,
                                "alert_type": atype,
                                "file_name":  fname,
                                "file_ref":   fref,
                                "detail":     detail,
                                "claimed_ts": None,
                                "actual_ts":  now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                            }
                            st.alerted_delete = True
                            # Reset state — file is gone
                            states.pop(fref, None)
                            first_seen_time.pop(fref, None)
                            # ── Detection 6: Disguised EXE masquerading as Office file ──
                    # Triggered when a file has an Office-like extension (e.g. .xlsx,
                    # .docx, .pptx) but its first 2 bytes are the PE magic "MZ"
                    # (0x4D 0x5A), proving the actual content is a Windows executable.
                    #
                    # Attack pattern (DROP_TIMESTOMP_DISGUISED_EXE):
                    #   1. Attacker renames malicious.exe → invoice.xlsx
                    #   2. Optionally timestomps it to blend into document history
                    #   3. Drops it on victim volume hoping AV/user ignores "xlsx" files
                    #
                    # Detection fires on CLOSE events for known Office extensions.
                    # We only read 2 bytes off disk — negligible I/O overhead.
                    # Magic bytes check is definitive: PKZIP (real Office) starts
                    # with PK (0x50 0x4B); PE executables always start with MZ.
                    #
                    # FALSE POSITIVE GUARD:
                    #   - Only fires on CLOSE (file fully written, bytes stable)
                    #   - Only checks extensions commonly abused for disguise
                    #   - Skips files < 64 bytes (corrupt / zero-byte placeholders)
                    #   - Dedup key prevents repeated alerts on same file

                    DISGUISE_OFFICE_EXTENSIONS = {
                        ".xlsx", ".xls", ".xlsm", ".xlsb",
                        ".docx", ".doc", ".docm",
                        ".pptx", ".ppt", ".pptm",
                        ".pdf", ".rtf", ".odt", ".ods", ".odp",
                        ".csv",
                    }

                    if is_close:
                        _ext = os.path.splitext(fname)[1].lower()
                        if _ext in DISGUISE_OFFICE_EXTENSIONS:
                            _fp = f"{d}:\\{fname}"
                            try:
                                _fsize = os.path.getsize(_fp)
                                if _fsize >= 64:
                                    with open(_fp, "rb") as _fh:
                                        _magic = _fh.read(2)
                                    if _magic == b"MZ":
                                        # Confirm it's truly a PE by checking offset 0x3C
                                        # (PE header pointer) — rules out coincidental MZ
                                        _is_pe = False
                                        _pe_off = 0
                                        try:
                                            with open(_fp, "rb") as _fh:
                                                _fh.seek(0x3C)
                                                _pe_off_raw = _fh.read(4)
                                                if len(_pe_off_raw) == 4:
                                                    _pe_off = struct.unpack_from("<I", _pe_off_raw)[0]
                                                    if 0x40 <= _pe_off < _fsize - 4:
                                                        _fh.seek(_pe_off)
                                                        _pe_sig = _fh.read(4)
                                                        if _pe_sig == b"PE\x00\x00":
                                                            _is_pe = True
                                        except Exception:
                                            _is_pe = True  # MZ without readable PE header — still suspicious

                                        _disguise_key = f"DROP_TIMESTOMP_DISGUISED_EXE_{fname}"
                                        _last_disguise = alert_dedup.get(_disguise_key)
                                        if not _last_disguise or (now_real - _last_disguise).total_seconds() > 30:
                                            _was_stomped = any(
                                                (r & 0x8000) and not (r & 0x7)
                                                for _, r, _ in st.history[-10:]
                                            )
                                            _stomp_note = (
                                                " File was also timestomped — timestamp manipulation "
                                                "detected alongside disguise, indicating deliberate evasion."
                                                if _was_stomped else ""
                                            )
                                            _pe_note = (
                                                f" (PE header at offset 0x{_pe_off:X} confirmed)"
                                                if _is_pe else
                                                " (MZ magic detected, PE header unreadable)"
                                            )
                                            alert = {
                                                "time":        now_real.isoformat(),
                                                "severity":    "CRITICAL",
                                                "alert_type":  "DROP_TIMESTOMP_DISGUISED_EXE",
                                                "file_name":   fname,
                                                "file_ref":    fref,
                                                "detail": (
                                                    f"'{fname}' has extension '{_ext}' but its magic bytes "
                                                    f"are MZ — this is a Windows PE executable disguised as "
                                                    f"an Office document.{_pe_note} "
                                                    f"Likely used to bypass file-type filters or deceive users."
                                                    f"{_stomp_note}"
                                                ),
                                                "claimed_ts":  None,
                                                "actual_ts":   now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                                "magic_bytes": "MZ (Windows PE executable)",
                                                "claimed_type": _ext,
                                            }
                                            alert_dedup[_disguise_key] = now_real
                            except (OSError, PermissionError):
                                pass  # File locked or deleted — skip silently

                    # ── Detection 7: Possible exfiltration (move off drive) ────
                    # RENAME_OLD_NAME fires when a file is renamed/moved.
                    # If we see RENAME_OLD but never see RENAME_NEW for the same
                    # file ref on this volume, the file was moved to a different
                    # volume (USB, network share, another drive) — exfiltration.
                    #
                    # We check pending rename_old records from previous USN poll
                    # cycles (files where rename_old_time was set but no
                    # rename_new arrived within 5 seconds on this volume).
                    if is_rename_new:
                        # RENAME_NEW arrived for this ref — cancel any pending exfil alert
                        st.rename_old_time = None
                        st.rename_old_name = None

                    # Scan all states for stale RENAME_OLD (no matching RENAME_NEW)
                    for ref_key, ref_st in list(states.items()):
                        if ref_st.rename_old_time is None:
                            continue
                        elapsed = (now_real - ref_st.rename_old_time).total_seconds()
                        if elapsed < 5.0:
                            continue  # still waiting for RENAME_NEW to arrive
                        # 5s passed with no RENAME_NEW → file left the volume
                        old_name = ref_st.rename_old_name or "<unknown>"
                        skip_exfil = "$recycle" in old_name.lower() or "~$" in old_name.lower()
                        if not skip_exfil:
                            was_stomped_exfil = any(
                                (r & 0x8000) and not (r & 0x7)
                                for _, r, _ in ref_st.history[-10:]
                            )
                            exfil_sev  = "CRITICAL" if was_stomped_exfil else "HIGH"
                            stomp_note = " File was also timestomped before being moved." if was_stomped_exfil else ""
                            exfil_key  = f"POSSIBLE_EXFILTRATION_{old_name}"
                            last_exfil = alert_dedup.get(exfil_key)
                            if not last_exfil or (now_real - last_exfil).total_seconds() > 30:
                                exfil_alert = {
                                    "time":       now_real.isoformat(),
                                    "severity":   exfil_sev,
                                    "alert_type": "POSSIBLE_EXFILTRATION",
                                    "file_name":  old_name,
                                    "file_ref":   ref_key,
                                    "detail":     (
                                        f"'{old_name}' was MOVED OFF {d}:\\ — "
                                        f"RENAME_OLD seen but no RENAME_NEW on this volume "
                                        f"within 5s. File was likely moved to USB, network "
                                        f"share, or another drive.{stomp_note}"
                                    ),
                                    "claimed_ts": None,
                                    "actual_ts":  now_real.strftime("%Y-%m-%d %H:%M:%S UTC"),
                                }
                                alert_dedup[exfil_key] = now_real
                                alerts.append(exfil_alert)
                                print()
                                print_alert(exfil_alert)
                                if output_file:
                                    with open(output_file, "w") as fw:
                                        json.dump({
                                            "monitor_start": monitor_start.isoformat(),
                                            "total_alerts":  len(alerts),
                                            "alerts":        alerts
                                        }, fw, indent=2)
                        # Clear the pending rename regardless
                        ref_st.rename_old_time = None
                        ref_st.rename_old_name = None

                    if alert:
                        # Deduplicate: same file + same alert type within 10 seconds = one alert
                        dedup_key = f"{alert['alert_type']}_{alert['file_name']}"
                        last_fired = alert_dedup.get(dedup_key)
                        if last_fired and (now_real - last_fired).total_seconds() < 10:
                            pass  # suppress duplicate
                        else:
                            alert_dedup[dedup_key] = now_real
                            alerts.append(alert)
                            print()
                            print_alert(alert)
                            if output_file:
                                with open(output_file, "w") as f:
                                    json.dump({
                                        "monitor_start": monitor_start.isoformat(),
                                        "total_alerts":  len(alerts),
                                        "alerts":        alerts
                                    }, f, indent=2)

                    off += rl
                except Exception:
                    off += 8

            time.sleep(poll_interval)

    except KeyboardInterrupt:
        print(f"\n\n[+] Monitor stopped.")
        print(f"[+] USN events processed : {events:,}")
        print(f"[+] Alerts generated     : {len(alerts)}")
        if output_file and alerts:
            with open(output_file, "w") as f:
                json.dump({
                    "monitor_start": monitor_start.isoformat(),
                    "total_alerts":  len(alerts),
                    "alerts":        alerts
                }, f, indent=2)
            print(f"[+] Saved to: {output_file}")

    k32.CloseHandle(h)
    if mft:
        mft.close()
    return alerts


if __name__ == "__main__":
    import argparse
    if sys.platform != "win32":
        print("[!] Live monitor only works on Windows.")
        sys.exit(1)
    p = argparse.ArgumentParser(description="NTFS Live Tampering Monitor v5")
    p.add_argument("--drive",    default="C")
    p.add_argument("--output",   default="alerts.json")
    p.add_argument("--interval", default=0.3, type=float)
    args = p.parse_args()
    monitor_live(drive=args.drive, output_file=args.output, poll_interval=args.interval)
