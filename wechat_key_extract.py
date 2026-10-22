"""Read SQLCipher key material from local WeChat memory without modifying it.

The current WeChat 4.1.13+ path is a narrow Python adaptation of the WCDB
``Config.Cipher`` decoder in fanyuantaier/wechatauto-replica 1.2.2.6
(Apache-2.0).  The legacy strict raw-key/salt literal scanner is adapted from
jackwener/wx-cli v0.3.0 (Apache-2.0) and remains for compatibility tests.

Both paths target only exact Weixin.exe and WeChat.exe process names in the
current Windows login session, request query/read access, never write target
process memory, and never persist extracted key material.
"""

from __future__ import annotations

import ctypes
import hashlib
import hmac
import os
import re
import struct
import time
from ctypes import wintypes
from dataclasses import dataclass, field
from typing import Callable, Collection


SOURCE_PROJECT = "jackwener/wx-cli"
SOURCE_VERSION = "v0.3.0"
SOURCE_URL = "https://github.com/jackwener/wx-cli"
CONFIG_CIPHER_SOURCE_PROJECT = "fanyuantaier/wechatauto-replica"
CONFIG_CIPHER_SOURCE_VERSION = "1.2.2.6"
CONFIG_CIPHER_SOURCE_URL = "https://github.com/fanyuantaier/wechatauto-replica"

PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
TH32CS_SNAPPROCESS = 0x00000002
MEM_COMMIT = 0x1000
PAGE_READWRITE = 0x04
PAGE_READONLY = 0x02
PAGE_WRITECOPY = 0x08
PAGE_EXECUTE_READ = 0x20
PAGE_EXECUTE_READWRITE = 0x40
PAGE_EXECUTE_WRITECOPY = 0x80
PAGE_GUARD = 0x100
PAGE_NOCACHE = 0x200
PAGE_WRITECOMBINE = 0x400
MAX_PATH = 260
HEX_PATTERN_LENGTH = 96
LITERAL_LENGTH = HEX_PATTERN_LENGTH + 3
CHUNK_SIZE = 2 * 1024 * 1024
MAX_MATCHING_CANDIDATES = 256
CONFIG_CIPHER_NAME = b"com.Tencent.WCDB.Config.Cipher"
CONFIG_XOR_MASK = bytes.fromhex(
    "d2c7442458020000004889442450488b"
    "450048844c2448488944254048584c24"
)
CONFIG_HEX_LITERAL_RE = re.compile(rb"[xX]'([0-9a-fA-F]{64,192})'")
SQLCIPHER_PAGE_SIZE = 4096
SQLCIPHER_RESERVE_SIZE = 80


class KeyExtractionError(RuntimeError):
    pass


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.c_size_t),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", wintypes.LONG),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * MAX_PATH),
    ]


class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("PartitionId", wintypes.WORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


@dataclass(frozen=True)
class WeChatProcess:
    pid: int
    name: str


@dataclass(frozen=True)
class KeyCandidate:
    key_hex: str
    salt_hex: str
    pid: int
    process_name: str


@dataclass
class KeyScanResult:
    match: KeyCandidate | None
    process_count: int
    opened_process_count: int
    denied_process_count: int
    candidate_count: int
    scanned_region_count: int
    scanned_bytes: int
    elapsed_seconds: float
    timed_out: bool = False
    access_errors: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class ConfigCipherCandidate:
    key_hex: str
    explicit_salt_hex: str | None
    pid: int
    process_name: str


@dataclass
class ConfigCipherScanResult:
    candidates: list[ConfigCipherCandidate]
    process_count: int
    opened_process_count: int
    denied_process_count: int
    scanned_region_count: int
    scanned_bytes: int
    config_name_hit_count: int
    config_reference_count: int
    decoded_blob_count: int
    elapsed_seconds: float
    access_errors: list[str] = field(default_factory=list)


_kernel32: object | None = None


def _get_kernel32():
    global _kernel32
    if os.name != "nt":
        raise KeyExtractionError("数据库密钥自动提取只支持 Windows。")
    if _kernel32 is not None:
        return _kernel32

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
    kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
    kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32FirstW.restype = wintypes.BOOL
    kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
    kernel32.Process32NextW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.GetCurrentProcessId.argtypes = []
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    kernel32.ProcessIdToSessionId.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    kernel32.ProcessIdToSessionId.restype = wintypes.BOOL
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.VirtualQueryEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t,
    ]
    kernel32.VirtualQueryEx.restype = ctypes.c_size_t
    kernel32.ReadProcessMemory.argtypes = [
        wintypes.HANDLE,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_size_t),
    ]
    kernel32.ReadProcessMemory.restype = wintypes.BOOL
    _kernel32 = kernel32
    return kernel32


def _windows_error(prefix: str) -> str:
    code = ctypes.get_last_error()
    try:
        detail = ctypes.FormatError(code).strip()
    except Exception:
        detail = ""
    return f"{prefix}（Windows 错误 {code}{'：' + detail if detail else ''}）"


def list_same_session_wechat_processes() -> list[WeChatProcess]:
    """Return exact-name WeChat processes in the current Windows session."""
    kernel32 = _get_kernel32()
    invalid_handle_value = ctypes.c_void_p(-1).value
    snapshot = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snapshot or snapshot == invalid_handle_value:
        raise KeyExtractionError(_windows_error("无法枚举 Windows 进程"))

    current_session = wintypes.DWORD()
    if not kernel32.ProcessIdToSessionId(
        kernel32.GetCurrentProcessId(), ctypes.byref(current_session)
    ):
        kernel32.CloseHandle(snapshot)
        raise KeyExtractionError(_windows_error("无法确认当前 Windows 登录会话"))

    wanted = {"weixin.exe", "wechat.exe"}
    found: list[WeChatProcess] = []
    entry = PROCESSENTRY32W()
    entry.dwSize = ctypes.sizeof(PROCESSENTRY32W)
    try:
        ok = kernel32.Process32FirstW(snapshot, ctypes.byref(entry))
        while ok:
            name = str(entry.szExeFile)
            pid = int(entry.th32ProcessID)
            if name.casefold() in wanted:
                session = wintypes.DWORD()
                if kernel32.ProcessIdToSessionId(pid, ctypes.byref(session)) and (
                    session.value == current_session.value
                ):
                    found.append(WeChatProcess(pid=pid, name=name))
            ok = kernel32.Process32NextW(snapshot, ctypes.byref(entry))
    finally:
        kernel32.CloseHandle(snapshot)
    return sorted(found, key=lambda item: item.pid)


def _is_writable_readable_page(protect: int) -> bool:
    base = protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)
    return base in {
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    } and not (protect & PAGE_GUARD)


def _is_readable_page(protect: int) -> bool:
    base = protect & ~(PAGE_GUARD | PAGE_NOCACHE | PAGE_WRITECOMBINE)
    return base in {
        PAGE_READONLY,
        PAGE_READWRITE,
        PAGE_WRITECOPY,
        PAGE_EXECUTE_READ,
        PAGE_EXECUTE_READWRITE,
        PAGE_EXECUTE_WRITECOPY,
    } and not (protect & PAGE_GUARD)


def verify_sqlcipher4_raw_key(page1: bytes, raw_key: bytes, salt: bytes | None = None) -> bool:
    """Verify a 32-byte raw key against an encrypted SQLCipher 4 first page."""
    if len(page1) < SQLCIPHER_PAGE_SIZE or len(raw_key) != 32:
        return False
    selected_salt = salt if salt is not None else page1[:16]
    if len(selected_salt) != 16:
        return False
    mac_salt = bytes(value ^ 0x3A for value in selected_salt)
    mac_key = hashlib.pbkdf2_hmac("sha512", raw_key, mac_salt, 2, dklen=32)
    hmac_data = page1[16 : SQLCIPHER_PAGE_SIZE - SQLCIPHER_RESERVE_SIZE + 16]
    stored_hmac = page1[SQLCIPHER_PAGE_SIZE - 64 : SQLCIPHER_PAGE_SIZE]
    digest = hmac.new(mac_key, hmac_data, hashlib.sha512)
    digest.update(struct.pack("<I", 1))
    return hmac.compare_digest(digest.digest(), stored_hmac)


def find_key_literals(
    buffer: bytes, target_salts: Collection[str] | None = None
) -> list[tuple[str, str]]:
    """Find strict x'<64 hex raw key><32 hex salt>' literals in a byte buffer."""
    target = None
    if target_salts is not None:
        target = {salt.casefold().encode("ascii") for salt in target_salts}
    results: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    start = 0
    while True:
        index = buffer.find(b"x'", start)
        if index < 0:
            break
        end = index + LITERAL_LENGTH
        start = index + 1
        if end > len(buffer) or buffer[end - 1] != ord("'"):
            continue
        payload = buffer[index + 2 : index + 2 + HEX_PATTERN_LENGTH]
        if not all(
            48 <= value <= 57 or 65 <= value <= 70 or 97 <= value <= 102
            for value in payload
        ):
            continue
        key_bytes = payload[:64].lower()
        salt_bytes = payload[64:].lower()
        if target is not None and salt_bytes not in target:
            continue
        pair = (key_bytes.decode("ascii"), salt_bytes.decode("ascii"))
        if pair not in seen:
            seen.add(pair)
            results.append(pair)
    return results


def _iter_region_literals(
    kernel32,
    process_handle,
    base: int,
    size: int,
    target_salts: Collection[str],
    stats: dict[str, int],
):
    overlap = LITERAL_LENGTH
    offset = 0
    while offset < size:
        chunk_size = min(CHUNK_SIZE, size - offset)
        address = base + offset
        buffer = ctypes.create_string_buffer(chunk_size)
        bytes_read = ctypes.c_size_t()
        ok = kernel32.ReadProcessMemory(
            process_handle,
            ctypes.c_void_p(address),
            buffer,
            chunk_size,
            ctypes.byref(bytes_read),
        )
        if (ok or bytes_read.value) and bytes_read.value:
            stats["bytes"] += int(bytes_read.value)
            payload = buffer.raw[: bytes_read.value]
            yield from find_key_literals(payload, target_salts)
        offset += chunk_size - overlap if chunk_size > overlap else chunk_size


def _iter_process_literals(
    kernel32,
    process_handle,
    target_salts: Collection[str],
    stats: dict[str, int],
    deadline: float,
):
    address = 0
    while time.monotonic() < deadline:
        info = MEMORY_BASIC_INFORMATION()
        returned = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(info),
            ctypes.sizeof(MEMORY_BASIC_INFORMATION),
        )
        if not returned:
            break
        base = int(info.BaseAddress or 0)
        size = int(info.RegionSize)
        next_address = base + size
        if size <= 0 or next_address <= address:
            break
        if info.State == MEM_COMMIT and _is_writable_readable_page(int(info.Protect)):
            stats["regions"] += 1
            yield from _iter_region_literals(
                kernel32, process_handle, base, size, target_salts, stats
            )
        address = next_address


def _read_process_bytes(kernel32, process_handle, address: int, size: int) -> bytes | None:
    if size <= 0:
        return None
    buffer = ctypes.create_string_buffer(size)
    bytes_read = ctypes.c_size_t()
    ok = kernel32.ReadProcessMemory(
        process_handle,
        ctypes.c_void_p(address),
        buffer,
        size,
        ctypes.byref(bytes_read),
    )
    if not ok and not bytes_read.value:
        return None
    return buffer.raw[: bytes_read.value]


def _iter_readable_regions(kernel32, process_handle):
    address = 0
    while True:
        info = MEMORY_BASIC_INFORMATION()
        returned = kernel32.VirtualQueryEx(
            process_handle,
            ctypes.c_void_p(address),
            ctypes.byref(info),
            ctypes.sizeof(MEMORY_BASIC_INFORMATION),
        )
        if not returned:
            return
        base = int(info.BaseAddress or 0)
        size = int(info.RegionSize)
        next_address = base + size
        if size <= 0 or next_address <= address:
            return
        if info.State == MEM_COMMIT and _is_readable_page(int(info.Protect)):
            yield base, size
        address = next_address


def _find_remote_patterns(
    kernel32,
    process_handle,
    patterns: Collection[bytes],
    stats: dict[str, int],
    *,
    max_hits: int = 4096,
) -> dict[bytes, list[int]]:
    """Find byte patterns in committed readable pages without modifying the process."""
    wanted = tuple(dict.fromkeys(value for value in patterns if value))
    hits: dict[bytes, list[int]] = {value: [] for value in wanted}
    if not wanted:
        return hits
    overlap = max(len(value) for value in wanted) - 1
    total_hits = 0
    for base, size in _iter_readable_regions(kernel32, process_handle):
        stats["regions"] += 1
        offset = 0
        while offset < size:
            chunk_size = min(CHUNK_SIZE, size - offset)
            payload = _read_process_bytes(
                kernel32, process_handle, base + offset, chunk_size
            )
            if payload:
                stats["bytes"] += len(payload)
                for pattern in wanted:
                    start = 0
                    while total_hits < max_hits:
                        index = payload.find(pattern, start)
                        if index < 0:
                            break
                        absolute = base + offset + index
                        bucket = hits[pattern]
                        if not bucket or bucket[-1] != absolute:
                            bucket.append(absolute)
                            total_hits += 1
                        start = index + 1
            if total_hits >= max_hits:
                return hits
            offset += chunk_size - overlap if chunk_size > overlap else chunk_size
    return hits


def _probable_raw_key(value: bytes) -> bool:
    return (
        len(value) == 32
        and len(set(value)) >= 15
        and value not in {b"\x00" * 32, b"\xff" * 32}
    )


def _config_cipher_candidates_from_process(
    kernel32,
    process_handle,
    process: WeChatProcess,
    stats: dict[str, int],
) -> tuple[list[ConfigCipherCandidate], int, int, int]:
    """Decode WCDB Config.Cipher objects from one WeChat process."""
    name_hits = _find_remote_patterns(
        kernel32, process_handle, (CONFIG_CIPHER_NAME,), stats
    )[CONFIG_CIPHER_NAME]
    if not name_hits:
        return [], 0, 0, 0
    reference_patterns = tuple(
        struct.pack("<Q", address) + struct.pack("<Q", len(CONFIG_CIPHER_NAME))
        for address in name_hits
    )
    reference_hits = _find_remote_patterns(
        kernel32, process_handle, reference_patterns, stats
    )
    qaddrs = [address for values in reference_hits.values() for address in values]
    output: list[ConfigCipherCandidate] = []
    seen: set[tuple[str, str | None]] = set()
    decoded_blobs = 0
    for qaddr in qaddrs:
        node = _read_process_bytes(kernel32, process_handle, qaddr - 0x10, 0x50)
        if not node or len(node) < 0x40:
            continue
        name_pointer = struct.unpack_from("<Q", node, 0x10)[0]
        name_length = struct.unpack_from("<Q", node, 0x18)[0]
        if name_pointer not in name_hits or name_length != len(CONFIG_CIPHER_NAME):
            continue
        config_pointer = struct.unpack_from("<Q", node, 0x28)[0]
        if not 0x10000 <= config_pointer < 0x800000000000:
            continue
        obj = _read_process_bytes(kernel32, process_handle, config_pointer + 0x88, 0x28)
        if not obj or len(obj) < 0x18:
            continue
        data_pointer = struct.unpack_from("<Q", obj, 0x08)[0]
        data_length = struct.unpack_from("<Q", obj, 0x10)[0]
        if not (0 < data_length <= 1024 and 0x10000 <= data_pointer < 0x800000000000):
            continue
        blob = _read_process_bytes(
            kernel32, process_handle, data_pointer, int(data_length)
        )
        if not blob or len(blob) != data_length:
            continue
        decoded_blobs += 1
        decoded = bytes(
            value ^ CONFIG_XOR_MASK[index % len(CONFIG_XOR_MASK)]
            for index, value in enumerate(blob)
        )
        for match in CONFIG_HEX_LITERAL_RE.finditer(decoded):
            run = match.group(1).decode("ascii").casefold()
            starts = [0]
            if len(run) > 96:
                starts.extend(range(0, len(run) - 63, 32))
                starts.append(len(run) - 64)
            for start in dict.fromkeys(starts):
                if start + 64 > len(run):
                    continue
                key = bytes.fromhex(run[start : start + 64])
                if not _probable_raw_key(key):
                    continue
                explicit_salt = (
                    run[start + 64 : start + 96]
                    if start + 96 <= len(run)
                    else None
                )
                identity = (key.hex(), explicit_salt)
                if identity in seen:
                    continue
                seen.add(identity)
                output.append(
                    ConfigCipherCandidate(
                        key_hex=identity[0],
                        explicit_salt_hex=explicit_salt,
                        pid=process.pid,
                        process_name=process.name,
                    )
                )
    return output, len(name_hits), len(qaddrs), decoded_blobs


def scan_config_cipher_candidates() -> ConfigCipherScanResult:
    """Read and decode Config.Cipher key material from same-session WeChat processes."""
    started = time.monotonic()
    processes = list_same_session_wechat_processes()
    if not processes:
        raise KeyExtractionError(
            "没有找到当前登录会话中的 Weixin.exe / WeChat.exe，请先启动微信并停留在登录界面。"
        )
    kernel32 = _get_kernel32()
    opened = denied = 0
    stats = {"regions": 0, "bytes": 0}
    name_hits = references = decoded_blobs = 0
    access_errors: list[str] = []
    output: list[ConfigCipherCandidate] = []
    seen: set[tuple[str, str | None]] = set()
    for process in processes:
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, process.pid
        )
        if not handle:
            denied += 1
            access_errors.append(_windows_error(f"无法读取 {process.name} PID {process.pid}"))
            continue
        opened += 1
        try:
            candidates, hit_count, reference_count, blob_count = (
                _config_cipher_candidates_from_process(
                    kernel32, handle, process, stats
                )
            )
            name_hits += hit_count
            references += reference_count
            decoded_blobs += blob_count
            for candidate in candidates:
                identity = (candidate.key_hex, candidate.explicit_salt_hex)
                if identity not in seen:
                    seen.add(identity)
                    output.append(candidate)
        finally:
            kernel32.CloseHandle(handle)
    return ConfigCipherScanResult(
        candidates=output,
        process_count=len(processes),
        opened_process_count=opened,
        denied_process_count=denied,
        scanned_region_count=stats["regions"],
        scanned_bytes=stats["bytes"],
        config_name_hit_count=name_hits,
        config_reference_count=references,
        decoded_blob_count=decoded_blobs,
        elapsed_seconds=time.monotonic() - started,
        access_errors=access_errors,
    )


def scan_for_verified_key(
    target_salts: Collection[str],
    validator: Callable[[KeyCandidate], bool],
    *,
    timeout_seconds: float = 120.0,
) -> KeyScanResult:
    """Scan fixed WeChat processes and return early only if validator requests it."""
    normalized_salts = {salt.casefold() for salt in target_salts}
    if not normalized_salts or any(
        len(salt) != 32 or any(char not in "0123456789abcdef" for char in salt)
        for salt in normalized_salts
    ):
        raise KeyExtractionError("数据库 salt 集合为空或格式无效。")

    started = time.monotonic()
    deadline = started + max(1.0, float(timeout_seconds))
    processes = list_same_session_wechat_processes()
    if not processes:
        raise KeyExtractionError("没有找到当前登录会话中的 Weixin.exe / WeChat.exe，请先启动并登录微信。")

    kernel32 = _get_kernel32()
    opened = 0
    denied = 0
    candidate_count = 0
    stats = {"regions": 0, "bytes": 0}
    access_errors: list[str] = []
    seen: set[tuple[str, str]] = set()

    for process in processes:
        if time.monotonic() >= deadline:
            break
        handle = kernel32.OpenProcess(
            PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, process.pid
        )
        if not handle:
            denied += 1
            access_errors.append(_windows_error(f"无法读取 {process.name} PID {process.pid}"))
            continue
        opened += 1
        try:
            for key_hex, salt_hex in _iter_process_literals(
                kernel32, handle, normalized_salts, stats, deadline
            ):
                pair = (key_hex, salt_hex)
                if pair in seen:
                    continue
                seen.add(pair)
                candidate_count += 1
                candidate = KeyCandidate(
                    key_hex=key_hex,
                    salt_hex=salt_hex,
                    pid=process.pid,
                    process_name=process.name,
                )
                if validator(candidate):
                    return KeyScanResult(
                        match=candidate,
                        process_count=len(processes),
                        opened_process_count=opened,
                        denied_process_count=denied,
                        candidate_count=candidate_count,
                        scanned_region_count=stats["regions"],
                        scanned_bytes=stats["bytes"],
                        elapsed_seconds=time.monotonic() - started,
                        access_errors=access_errors,
                    )
                if candidate_count >= MAX_MATCHING_CANDIDATES:
                    break
        finally:
            kernel32.CloseHandle(handle)
        if candidate_count >= MAX_MATCHING_CANDIDATES:
            break

    return KeyScanResult(
        match=None,
        process_count=len(processes),
        opened_process_count=opened,
        denied_process_count=denied,
        candidate_count=candidate_count,
        scanned_region_count=stats["regions"],
        scanned_bytes=stats["bytes"],
        elapsed_seconds=time.monotonic() - started,
        timed_out=time.monotonic() >= deadline,
        access_errors=access_errors,
    )
