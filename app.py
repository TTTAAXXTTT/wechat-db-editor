from __future__ import annotations

import base64
import hashlib
import json
import logging
import mimetypes
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
import webbrowser
from contextlib import contextmanager
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

import zstandard as zstd
from sqlcipher3 import dbapi2 as sqlcipher

import wechat_key_extract as key_extract


APP_NAME = "微信数据库副本编辑器"
APP_VERSION = "2.0.0"
SNAPSHOT_VERSION = 1
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_TEXT_BYTES = 16 * 1024 * 1024
SESSION_SUMMARY_MAX_BYTES = 200
MAX_INSERT_TEXT_CHARS = 200_000
LOCAL_INSERT_SOURCE_MARKER = "codex-wechat-local-insert-v1"
LOCAL_INSERT_SOURCE = (
    f"<msgsource><localonly>{LOCAL_INSERT_SOURCE_MARKER}</localonly>"
    "<direction>self</direction></msgsource>"
)
LOCAL_INSERT_OTHER_SOURCE = (
    f"<msgsource><localonly>{LOCAL_INSERT_SOURCE_MARKER}</localonly>"
    "<direction>other</direction></msgsource>"
)
LOCAL_SERVER_ID_PREFIX = 0x7E00000000000000
MESSAGE_DB_RE = re.compile(r"^(?:message_\d+|biz_message_\d+)\.db$", re.I)
TABLE_RE = re.compile(r"^Msg_[0-9a-f]{32}$", re.I)
HEX_KEY_RE = re.compile(r"^[0-9a-fA-F]{64}$")
KEY_BUNDLE_PREFIX = "WCKEY1:"
KEY_BUNDLE_FORMAT = "wechat-db-keyring"
KEY_BUNDLE_VERSION = 1
ZSTD_MAGIC = b"\x28\xb5\x2f\xfd"


def app_base_dir() -> Path:
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


STATIC_DIR = app_base_dir() / "static"
DEFAULT_PAGE = "index.html"


def distribution_base_dir() -> Path:
    """Return the distributed folder, not PyInstaller's temporary extraction dir."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


def setup_logging() -> None:
    log_dir = Path(os.environ.get("LOCALAPPDATA", Path.home())) / "WeChatCopyEditor"
    log_dir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=log_dir / "app.log",
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )


class AppError(Exception):
    def __init__(self, message: str, status: int = HTTPStatus.BAD_REQUEST):
        super().__init__(message)
        self.status = int(status)


class EditorState:
    def __init__(self) -> None:
        self.guard = threading.RLock()
        self.snapshot_root: Path | None = None
        self.source_root: Path | None = None
        self.manifest: dict[str, Any] | None = None
        self.mode: str | None = None
        self._key: bytearray | None = None
        self._raw_keys: dict[str, bytearray] = {}
        self.extracted_source_root: Path | None = None
        self.conversations_cache: list[dict[str, Any]] | None = None
        self.contacts_cache: dict[str, str] | None = None
        self.jobs: dict[str, dict[str, Any]] = {}
        self.capture: dict[str, Any] = {"status": "idle"}
        self.capture_cancel: threading.Event | None = None
        self.capture_thread: threading.Thread | None = None

    def clear_key(self) -> None:
        with self.guard:
            if self._key is not None:
                for index in range(len(self._key)):
                    self._key[index] = 0
            self._key = None
            for raw_key in self._raw_keys.values():
                for index in range(len(raw_key)):
                    raw_key[index] = 0
            self._raw_keys = {}
            self.extracted_source_root = None
            self.conversations_cache = None
            self.contacts_cache = None

    def set_key(self, value: bytes) -> None:
        self.clear_key()
        with self.guard:
            self._key = bytearray(value)

    def set_raw_keys(self, source: Path, values: dict[str, bytes]) -> None:
        self.clear_key()
        normalized: dict[str, bytearray] = {}
        for salt, value in values.items():
            normalized_salt = str(salt).casefold()
            if not re.fullmatch(r"[0-9a-f]{32}", normalized_salt):
                raise AppError("提取结果包含格式无效的数据库 salt。")
            if len(value) != 32:
                raise AppError("提取结果包含长度无效的 SQLCipher raw key。")
            normalized[normalized_salt] = bytearray(value)
        if not normalized:
            raise AppError("没有可保存到内存的数据库 raw key。")
        with self.guard:
            self._raw_keys = normalized
            self.extracted_source_root = source.resolve()

    def clear_session(self) -> None:
        with self.guard:
            if self.capture_cancel is not None:
                self.capture_cancel.set()
            self.capture = {"status": "idle"}
            self.capture_cancel = None
            self.capture_thread = None
            self.snapshot_root = None
            self.source_root = None
            self.manifest = None
            self.mode = None
            self.jobs.clear()
            self.clear_key()

    def key_bytes(self) -> bytes:
        with self.guard:
            if self._key is None:
                target = "源数据库" if self.mode == "direct" else "副本"
                raise AppError(f"{target}尚未解锁，请先输入数据库密钥。", HTTPStatus.LOCKED)
            return bytes(self._key)

    def master_key_bytes(self) -> bytes | None:
        with self.guard:
            return bytes(self._key) if self._key is not None else None

    def raw_key_for_path(self, path: Path) -> bytes:
        salt = encrypted_database_salt(path)
        with self.guard:
            value = self._raw_keys.get(str(salt or "").casefold())
            if value is None:
                raise AppError(
                    f"内存密钥环中没有 {path.name} 对应的 raw key。",
                    HTTPStatus.LOCKED,
                )
            return bytes(value)

    def extracted_keys_match(self, source: Path) -> bool:
        with self.guard:
            return bool(
                self._raw_keys
                and self.extracted_source_root is not None
                and self.extracted_source_root == source.resolve()
            )

    @property
    def raw_key_count(self) -> int:
        with self.guard:
            return len(self._raw_keys)

    @property
    def unlocked(self) -> bool:
        with self.guard:
            return self._key is not None or bool(self._raw_keys)


STATE = EditorState()
MUTATION_LOCK = threading.Lock()
SERVER: ThreadingHTTPServer | None = None
SESSION_TOKEN = secrets.token_urlsafe(32)


def iso_now() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def human_size(value: int) -> str:
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{value} B"


def resolved(path: str | Path) -> Path:
    return Path(path).expanduser().resolve(strict=False)


def norm_path(path: Path) -> str:
    return os.path.normcase(os.path.abspath(str(path)))


def paths_overlap(first: Path, second: Path) -> bool:
    a, b = norm_path(first), norm_path(second)
    try:
        common = os.path.commonpath([a, b])
    except ValueError:
        return False
    return common == a or common == b


def ensure_separate_paths(source: Path, target: Path) -> None:
    if paths_overlap(source, target):
        raise AppError("工作目录不能与微信源目录相同，也不能互相包含。请选择完全独立的目录。")


def account_root_from_input(value: str) -> Path:
    if not value.strip():
        raise AppError("请手动填写微信账号目录。")
    candidate = resolved(value)
    if candidate.name.lower() == "db_storage":
        candidate = candidate.parent
    if not candidate.is_dir():
        raise AppError(f"源账号目录不存在：{candidate}")
    db_storage = candidate / "db_storage"
    if not db_storage.is_dir():
        raise AppError("所选目录中没有 db_storage，请选择微信账号目录。")
    message_dir = db_storage / "message"
    if not message_dir.is_dir() or not any(
        MESSAGE_DB_RE.match(path.name) for path in message_dir.glob("*.db")
    ):
        raise AppError("没有找到 message_*.db 聊天分片，请确认账号目录是否正确。")
    return candidate


def is_database_related(path: Path) -> bool:
    name = path.name.lower()
    return bool(
        name.endswith(".db")
        or name.endswith(".db-wal")
        or name.endswith(".db-shm")
        or name.endswith(".db-first.material")
        or name.endswith(".db-last.material")
        or name.endswith(".db-incremental.material")
        or name.endswith(".kvdb")
        or name.endswith(".kvdb-wal")
        or name.endswith(".kvdb-shm")
    )


def is_working_related(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".db") or name.endswith(".db-wal")


def source_candidates(account_root: Path) -> list[Path]:
    db_storage = account_root / "db_storage"
    return sorted(
        (path for path in db_storage.rglob("*") if path.is_file() and is_database_related(path)),
        key=lambda item: str(item).lower(),
    )


def running_weixin_processes() -> list[str]:
    if os.name != "nt":
        return []
    command = ["tasklist", "/FO", "CSV", "/NH"]
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=flags,
            timeout=10,
            check=False,
        )
    except Exception:
        return []
    found: list[str] = []
    for line in result.stdout.splitlines():
        lower = line.lower()
        if '"weixin.exe"' in lower or '"wechat.exe"' in lower:
            found.append(line.split(",", 1)[0].strip().strip('"'))
    return sorted(set(found))


def nearest_existing_parent(path: Path) -> Path:
    current = path
    while not current.exists() and current.parent != current:
        current = current.parent
    return current


def copy_with_hash(source: Path, destination: Path) -> tuple[str, int, int]:
    before = source.stat()
    destination.parent.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256()
    total = 0
    with source.open("rb") as input_stream, destination.open("xb") as output_stream:
        while True:
            chunk = input_stream.read(4 * 1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
            output_stream.write(chunk)
            total += len(chunk)
        output_stream.flush()
        os.fsync(output_stream.fileno())
    shutil.copystat(source, destination, follow_symlinks=True)
    after = source.stat()
    if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
        raise AppError(f"复制期间源文件发生变化，快照已中止：{source.name}")
    if total != before.st_size:
        raise AppError(f"复制长度不一致，快照已中止：{source.name}")
    return digest.hexdigest(), before.st_size, before.st_mtime_ns


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(4 * 1024 * 1024)
            if not chunk:
                return digest.hexdigest()
            digest.update(chunk)


def update_job(job_id: str, **values: Any) -> None:
    with STATE.guard:
        job = STATE.jobs[job_id]
        job.update(values)
        job["updated_at"] = iso_now()


def snapshot_worker(job_id: str, source_text: str, target_text: str) -> None:
    try:
        source = account_root_from_input(source_text)
        target = resolved(target_text)
        ensure_separate_paths(source, target)
        processes = running_weixin_processes()
        if processes:
            raise AppError(
                "检测到微信仍在运行（"
                + "、".join(processes)
                + "）。请先从微信菜单正常退出，再创建快照；程序不会强制结束微信。"
            )
        if target.exists() and any(target.iterdir()):
            raise AppError("目标工作目录已经存在且非空。为避免覆盖，请换一个新目录。")

        files = source_candidates(source)
        if not files:
            raise AppError("没有发现可复制的数据库文件。")
        raw_bytes = sum(path.stat().st_size for path in files)
        working_bytes = sum(path.stat().st_size for path in files if is_working_related(path))
        required = raw_bytes + working_bytes + 512 * 1024 * 1024
        free = shutil.disk_usage(nearest_existing_parent(target)).free
        if free < required:
            raise AppError(
                f"磁盘空间不足：预计至少需要 {human_size(required)}，当前可用 {human_size(free)}。"
            )

        target.mkdir(parents=True, exist_ok=True)
        marker = target / ".snapshot_incomplete"
        marker.write_text("snapshot in progress\n", encoding="utf-8")
        raw_root = target / "original_encrypted"
        work_root = target / "working_encrypted"
        raw_root.mkdir()
        work_root.mkdir()
        copied_bytes = 0
        total_copy_bytes = raw_bytes + working_bytes
        records: list[dict[str, Any]] = []
        update_job(
            job_id,
            phase="copying",
            file_count=len(files),
            total_bytes=total_copy_bytes,
            copied_bytes=0,
            message=f"准备复制 {len(files)} 个数据库相关文件",
        )

        for index, source_file in enumerate(files, 1):
            relative = source_file.relative_to(source)
            raw_destination = raw_root / relative
            update_job(job_id, message=f"复制原始快照：{relative.as_posix()} ({index}/{len(files)})")
            digest, size, mtime_ns = copy_with_hash(source_file, raw_destination)
            copied_bytes += size
            try:
                raw_destination.chmod(stat.S_IREAD)
            except OSError:
                pass

            working_copy = is_working_related(source_file)
            if working_copy:
                work_destination = work_root / relative
                update_job(job_id, message=f"建立编辑层：{relative.as_posix()} ({index}/{len(files)})")
                work_destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(raw_destination, work_destination)
                if hash_file(work_destination) != digest:
                    raise AppError(f"编辑层副本哈希校验失败：{relative.as_posix()}")
                try:
                    work_destination.chmod(stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
                copied_bytes += size

            records.append(
                {
                    "relative": relative.as_posix(),
                    "size": size,
                    "mtime_ns": mtime_ns,
                    "sha256": digest,
                    "working_copy": working_copy,
                }
            )
            update_job(job_id, copied_bytes=copied_bytes)

        manifest = {
            "snapshot_version": SNAPSHOT_VERSION,
            "app_version": APP_VERSION,
            "created_at": iso_now(),
            "source_root": str(source),
            "source_db_storage": str(source / "db_storage"),
            "original_encrypted": "original_encrypted",
            "working_encrypted": "working_encrypted",
            "source_was_read_only": True,
            "database_files": len(files),
            "raw_bytes": raw_bytes,
            "working_bytes": working_bytes,
            "files": records,
        }
        temporary_manifest = target / "snapshot_manifest.json.tmp"
        temporary_manifest.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        temporary_manifest.replace(target / "snapshot_manifest.json")
        marker.unlink(missing_ok=True)

        with STATE.guard:
            STATE.clear_key()
            STATE.snapshot_root = target
            STATE.source_root = source
            STATE.manifest = manifest
            STATE.mode = "snapshot"
        update_job(
            job_id,
            status="completed",
            phase="complete",
            copied_bytes=total_copy_bytes,
            snapshot_root=str(target),
            message="快照与编辑层均已创建并完成哈希校验。",
        )
        logging.info("Snapshot created: %s from %s", target, source)
    except Exception as exc:
        message = str(exc) if isinstance(exc, AppError) else "创建快照失败，请查看程序日志。"
        logging.exception("Snapshot job failed")
        update_job(job_id, status="failed", phase="failed", error=message, message=message)


def start_snapshot(source: str, target: str) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    job = {
        "id": job_id,
        "type": "snapshot",
        "status": "running",
        "phase": "preflight",
        "created_at": iso_now(),
        "updated_at": iso_now(),
        "copied_bytes": 0,
        "total_bytes": 0,
        "message": "正在执行安全检查",
    }
    with STATE.guard:
        STATE.jobs[job_id] = job
    thread = threading.Thread(
        target=snapshot_worker,
        args=(job_id, source, target),
        name=f"snapshot-{job_id[:8]}",
        daemon=True,
    )
    thread.start()
    return job


def load_snapshot(path_text: str) -> dict[str, Any]:
    root = resolved(path_text)
    manifest_path = root / "snapshot_manifest.json"
    if not manifest_path.is_file():
        raise AppError("该目录不是有效快照：缺少 snapshot_manifest.json。")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise AppError("快照清单无法读取。") from exc
    if manifest.get("snapshot_version") != SNAPSHOT_VERSION:
        raise AppError("快照版本与当前程序不兼容。")
    work_root = root / manifest.get("working_encrypted", "working_encrypted")
    raw_root = root / manifest.get("original_encrypted", "original_encrypted")
    if not work_root.is_dir() or not raw_root.is_dir():
        raise AppError("快照缺少原始层或编辑层目录。")
    source = resolved(manifest.get("source_root", ""))
    ensure_separate_paths(source, root)
    with STATE.guard:
        STATE.clear_key()
        STATE.snapshot_root = root
        STATE.source_root = source
        STATE.manifest = manifest
        STATE.mode = "snapshot"
    logging.info("Snapshot loaded: %s", root)
    return snapshot_summary()


def snapshot_summary() -> dict[str, Any]:
    with STATE.guard:
        manifest = STATE.manifest or {}
        return {
            "loaded": STATE.snapshot_root is not None,
            "root": str(STATE.snapshot_root) if STATE.snapshot_root else None,
            "source_root": str(STATE.source_root) if STATE.source_root else None,
            "created_at": manifest.get("created_at"),
            "database_files": manifest.get("database_files"),
            "raw_bytes": manifest.get("raw_bytes"),
            "working_bytes": manifest.get("working_bytes"),
            "unlocked": STATE.unlocked,
        }


def working_root() -> Path:
    with STATE.guard:
        if STATE.mode == "direct":
            if STATE.source_root is None:
                raise AppError("尚未打开微信源目录。")
            return STATE.source_root
        if STATE.snapshot_root is None or STATE.manifest is None:
            raise AppError("请先创建或打开快照。")
        return STATE.snapshot_root / STATE.manifest.get("working_encrypted", "working_encrypted")


def safe_working_db(relative: str) -> Path:
    if not relative or Path(relative).is_absolute():
        raise AppError("数据库相对路径无效。")
    root = working_root().resolve()
    candidate = (root / Path(relative.replace("/", os.sep))).resolve(strict=False)
    if not candidate.is_relative_to(root) or candidate.suffix.lower() != ".db":
        raise AppError("数据库路径越出了当前账号目录。")
    if not candidate.is_file():
        raise AppError("目标数据库不存在。")
    return candidate


def message_database_paths() -> list[Path]:
    root = working_root()
    message_dir = root / "db_storage" / "message"
    if not message_dir.is_dir():
        return []
    return sorted(
        (path for path in message_dir.glob("*.db") if MESSAGE_DB_RE.match(path.name)),
        key=lambda path: [int(part) if part.isdigit() else part for part in re.split(r"(\d+)", path.name)],
    )


def apply_sqlcipher_key(
    connection: Any,
    path: Path,
    *,
    key: bytes | None = None,
    raw_key: bytes | None = None,
) -> str:
    """Apply either the account passphrase or a salt-bound SQLCipher raw key."""
    if key is not None and raw_key is not None:
        raise AppError("不能同时指定账号密钥和数据库 raw key。")
    selected_key = key
    selected_raw_key = raw_key
    if selected_key is None and selected_raw_key is None:
        selected_key = STATE.master_key_bytes()
        if selected_key is None:
            selected_raw_key = STATE.raw_key_for_path(path)
    if selected_raw_key is not None:
        if len(selected_raw_key) != 32:
            raise AppError("SQLCipher raw key 必须是 32 字节。")
        salt = encrypted_database_salt(path)
        if salt is None:
            raise AppError(f"无法读取 {path.name} 的 SQLCipher salt。")
        raw_literal = selected_raw_key.hex() + salt
        connection.execute(f"PRAGMA key = \"x'{raw_literal}'\"")
        return "raw"
    if selected_key is None:
        raise AppError("数据库尚未解锁。", HTTPStatus.LOCKED)
    connection.set_key(selected_key)
    return "passphrase"


@contextmanager
def encrypted_connection(
    path: Path,
    *,
    key: bytes | None = None,
    raw_key: bytes | None = None,
):
    connection = sqlcipher.connect(str(path), timeout=30)
    try:
        connection.row_factory = sqlcipher.Row
        apply_sqlcipher_key(connection, path, key=key, raw_key=raw_key)
        connection.execute("PRAGMA busy_timeout = 10000")
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
    finally:
        connection.close()


@contextmanager
def readonly_encrypted_connection(
    path: Path,
    *,
    key: bytes | None = None,
    raw_key: bytes | None = None,
):
    """Open one encrypted database without allowing SQLite to modify the source file."""
    uri = path.resolve().as_uri() + "?mode=ro"
    connection = sqlcipher.connect(uri, timeout=10, uri=True)
    try:
        connection.row_factory = sqlcipher.Row
        apply_sqlcipher_key(connection, path, key=key, raw_key=raw_key)
        connection.execute("PRAGMA query_only = ON")
        connection.execute("PRAGMA busy_timeout = 5000")
        yield connection
    finally:
        connection.close()


def validate_database_key_readonly(path: Path, key: bytes) -> bool:
    try:
        with readonly_encrypted_connection(path, key=key) as connection:
            row = connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            return row is not None and int(row[0]) >= 0
    except Exception:
        return False


def validate_database_raw_key_readonly(path: Path, raw_key: bytes) -> bool:
    try:
        with readonly_encrypted_connection(path, raw_key=raw_key) as connection:
            row = connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            return row is not None and int(row[0]) >= 0
    except Exception:
        return False


def encrypted_database_salt(path: Path) -> str | None:
    try:
        with path.open("rb") as stream:
            header = stream.read(16)
    except OSError:
        return None
    if len(header) != 16 or header[:15] == b"SQLite format 3":
        return None
    return header.hex()


def editor_database_paths(source: Path) -> list[Path]:
    message_dir = source / "db_storage" / "message"
    databases: list[Path] = sorted(
        (path for path in message_dir.glob("*.db") if MESSAGE_DB_RE.match(path.name)),
        key=lambda path: [
            int(part) if part.isdigit() else part.casefold()
            for part in re.split(r"(\d+)", path.name)
        ],
    )
    for relative in (
        Path("db_storage/contact/contact.db"),
        Path("db_storage/session/session.db"),
    ):
        candidate = source / relative
        if candidate.is_file():
            databases.append(candidate)
    return databases


def database_key_context(source: Path) -> tuple[list[Path], dict[str, list[Path]], dict[str, bytes]]:
    databases = editor_database_paths(source)
    if not databases:
        raise AppError("账号目录中没有编辑器需要的聊天、联系人或会话数据库。")
    paths_by_salt: dict[str, list[Path]] = {}
    pages_by_salt: dict[str, bytes] = {}
    for database in databases:
        salt = encrypted_database_salt(database)
        if salt is None:
            raise AppError(
                f"{database.relative_to(source).as_posix()} 没有可用于验证的 SQLCipher salt。"
            )
        normalized = salt.casefold()
        paths_by_salt.setdefault(normalized, []).append(database)
        if normalized not in pages_by_salt:
            try:
                with database.open("rb") as stream:
                    pages_by_salt[normalized] = stream.read(key_extract.SQLCIPHER_PAGE_SIZE)
            except OSError as exc:
                raise AppError(f"无法只读检查数据库：{database.name}") from exc
    return databases, paths_by_salt, pages_by_salt


def keyring_fingerprint(raw_keys: dict[str, bytes]) -> str:
    fingerprint_source = b"".join(
        bytes.fromhex(salt) + hashlib.sha256(raw_keys[salt]).digest()
        for salt in sorted(raw_keys)
    )
    return hashlib.sha256(fingerprint_source).hexdigest()[:12]


def collect_config_cipher_keys(
    source: Path,
    existing: dict[str, bytes] | None = None,
) -> tuple[dict[str, bytes], set[Path], set[str], key_extract.ConfigCipherScanResult]:
    databases, paths_by_salt, pages_by_salt = database_key_context(source)
    raw_keys = dict(existing or {})
    validated_paths: set[Path] = set()
    for salt in raw_keys:
        validated_paths.update(paths_by_salt.get(salt, []))
    process_labels: set[str] = set()
    try:
        scan = key_extract.scan_config_cipher_candidates()
    except key_extract.KeyExtractionError as exc:
        raise AppError(str(exc)) from exc
    if scan.opened_process_count == 0:
        detail = scan.access_errors[0] if scan.access_errors else "没有可读取的微信进程"
        raise AppError(
            f"{detail}。请确认微信与本工具由同一个 Windows 用户运行。"
        )

    for candidate in scan.candidates:
        key_buffer = bytearray.fromhex(candidate.key_hex)
        try:
            raw_key = bytes(key_buffer)
            for salt, paths in paths_by_salt.items():
                if salt in raw_keys:
                    continue
                page1 = pages_by_salt[salt]
                if not key_extract.verify_sqlcipher4_raw_key(page1, raw_key):
                    continue
                if not validate_database_raw_key_readonly(paths[0], raw_key):
                    continue
                raw_keys[salt] = raw_key
                validated_paths.update(paths)
                process_labels.add(f"{candidate.process_name} (PID {candidate.pid})")
        finally:
            for index in range(len(key_buffer)):
                key_buffer[index] = 0
    # Keep only salts that belong to the selected directory.
    raw_keys = {salt: value for salt, value in raw_keys.items() if salt in paths_by_salt}
    return raw_keys, validated_paths, process_labels, scan


def extraction_result(
    source: Path,
    raw_keys: dict[str, bytes],
    validated_paths: set[Path],
    process_labels: set[str],
    scan: key_extract.ConfigCipherScanResult,
) -> dict[str, Any]:
    databases = editor_database_paths(source)
    return {
        "fingerprint": keyring_fingerprint(raw_keys),
        "process": "、".join(sorted(process_labels)),
        "process_count": scan.process_count,
        "opened_process_count": scan.opened_process_count,
        "candidate_count": len(scan.candidates),
        "config_name_hit_count": scan.config_name_hit_count,
        "config_reference_count": scan.config_reference_count,
        "decoded_blob_count": scan.decoded_blob_count,
        "key_count": len(raw_keys),
        "required_database_count": len(databases),
        "validated_database_count": len(validated_paths),
        "scanned_bytes": scan.scanned_bytes,
        "scanned_human": human_size(scan.scanned_bytes),
        "elapsed_seconds": round(scan.elapsed_seconds, 2),
        "persisted": False,
        "stored_in_memory": True,
        "read_only": True,
        "source_project": key_extract.CONFIG_CIPHER_SOURCE_PROJECT,
        "source_version": key_extract.CONFIG_CIPHER_SOURCE_VERSION,
        "key_mode": "sqlcipher-raw-keyring",
        "extraction_method": "wcdb-config-cipher",
    }


def extract_database_key(source_text: str) -> dict[str, Any]:
    """Extract and validate the complete per-database keyring in one read-only pass."""
    source = account_root_from_input(source_text)
    raw_keys, validated_paths, process_labels, scan = collect_config_cipher_keys(source)
    databases = editor_database_paths(source)
    missing = [path for path in databases if path not in validated_paths]
    if missing:
        missing_text = "、".join(path.relative_to(source).as_posix() for path in missing[:8])
        suffix = " 等" if len(missing) > 8 else ""
        raise AppError(
            f"已验真 {len(validated_paths)}/{len(databases)} 个编辑必需数据库，仍缺少："
            f"{missing_text}{suffix}。请从登录界面先启动等待提取，再登录微信。"
        )
    STATE.set_raw_keys(source, raw_keys)
    logging.info(
        "Verified %s Config.Cipher WeChat raw keys for %s required databases",
        len(raw_keys),
        len(databases),
    )
    return extraction_result(
        source, raw_keys, validated_paths, process_labels, scan
    )


def export_key_bundle() -> dict[str, Any]:
    with STATE.guard:
        if not STATE._raw_keys:
            raise AppError("当前会话没有可复制的数据库密钥环。", HTTPStatus.LOCKED)
        keys = {salt: bytes(value).hex() for salt, value in STATE._raw_keys.items()}
    payload = {
        "format": KEY_BUNDLE_FORMAT,
        "version": KEY_BUNDLE_VERSION,
        "mode": "raw-keyring",
        "keys": dict(sorted(keys.items())),
    }
    encoded = base64.urlsafe_b64encode(
        json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ).decode("ascii").rstrip("=")
    return {
        "bundle": KEY_BUNDLE_PREFIX + encoded,
        "key_count": len(keys),
        "fingerprint": keyring_fingerprint(
            {salt: bytes.fromhex(value) for salt, value in keys.items()}
        ),
        "persisted": False,
    }


def decode_key_bundle(text: str) -> dict[str, bytes]:
    value = text.strip()
    if not value.startswith(KEY_BUNDLE_PREFIX):
        raise AppError("密钥包格式无效，应以 WCKEY1: 开头。")
    encoded = value[len(KEY_BUNDLE_PREFIX) :]
    if not encoded or len(encoded) > 64 * 1024:
        raise AppError("密钥包为空或过大。")
    try:
        padding = "=" * (-len(encoded) % 4)
        payload = json.loads(
            base64.b64decode(encoded + padding, altchars=b"-_", validate=True).decode(
                "utf-8"
            )
        )
    except Exception as exc:
        raise AppError("密钥包无法解析，请确认复制内容完整。") from exc
    if not isinstance(payload, dict) or payload.get("format") != KEY_BUNDLE_FORMAT:
        raise AppError("密钥包类型不受支持。")
    if payload.get("version") != KEY_BUNDLE_VERSION or payload.get("mode") != "raw-keyring":
        raise AppError("密钥包版本或模式不受支持。")
    values = payload.get("keys")
    if not isinstance(values, dict) or not values:
        raise AppError("密钥包中没有数据库密钥。")
    raw_keys: dict[str, bytes] = {}
    for salt, raw_key in values.items():
        normalized_salt = str(salt).casefold()
        normalized_key = str(raw_key).casefold()
        if not re.fullmatch(r"[0-9a-f]{32}", normalized_salt):
            raise AppError("密钥包包含格式无效的数据库 salt。")
        if not re.fullmatch(r"[0-9a-f]{64}", normalized_key):
            raise AppError("密钥包包含格式无效的数据库 raw key。")
        raw_keys[normalized_salt] = bytes.fromhex(normalized_key)
    return raw_keys


def import_key_bundle(source: Path, text: str) -> dict[str, Any]:
    supplied = decode_key_bundle(text)
    databases, paths_by_salt, pages_by_salt = database_key_context(source)
    imported: dict[str, bytes] = {}
    validated_paths: set[Path] = set()
    for salt, paths in paths_by_salt.items():
        raw_key = supplied.get(salt)
        if raw_key is None:
            continue
        if not key_extract.verify_sqlcipher4_raw_key(pages_by_salt[salt], raw_key):
            continue
        if not validate_database_raw_key_readonly(paths[0], raw_key):
            continue
        imported[salt] = raw_key
        validated_paths.update(paths)
    missing = [path for path in databases if path not in validated_paths]
    if missing:
        missing_text = "、".join(path.relative_to(source).as_posix() for path in missing[:8])
        suffix = " 等" if len(missing) > 8 else ""
        raise AppError(
            f"密钥包只通过 {len(validated_paths)}/{len(databases)} 个数据库验真，"
            f"仍缺少：{missing_text}{suffix}。"
        )
    STATE.set_raw_keys(source, imported)
    return {
        "key_count": len(imported),
        "validated_database_count": len(validated_paths),
        "required_database_count": len(databases),
        "fingerprint": keyring_fingerprint(imported),
        "persisted": False,
    }


def _capture_update(capture_id: str, **values: Any) -> bool:
    with STATE.guard:
        if STATE.capture.get("capture_id") != capture_id:
            return False
        STATE.capture.update(values)
        return True


def key_capture_worker(
    capture_id: str,
    source: Path,
    cancel: threading.Event,
    timeout_seconds: float,
) -> None:
    deadline = time.monotonic() + timeout_seconds
    raw_keys: dict[str, bytes] = {}
    attempts = 0
    accumulated_bytes = 0
    try:
        databases = editor_database_paths(source)
        while time.monotonic() < deadline and not cancel.is_set():
            processes = key_extract.list_same_session_wechat_processes()
            if not processes:
                _capture_update(
                    capture_id,
                    status="waiting_for_weixin",
                    message="等待微信启动。请重新打开微信并停留在登录界面。",
                    process_count=0,
                )
                cancel.wait(1.0)
                continue
            attempts += 1
            _capture_update(
                capture_id,
                status="scanning",
                message="正在等待登录并读取 WCDB 初始化密钥；现在可以登录微信。",
                process_count=len(processes),
                attempts=attempts,
            )
            try:
                raw_keys, validated, labels, scan = collect_config_cipher_keys(
                    source, raw_keys
                )
            except AppError as exc:
                _capture_update(
                    capture_id,
                    status="waiting_for_login",
                    message=str(exc),
                    attempts=attempts,
                )
                cancel.wait(2.0)
                continue
            accumulated_bytes += scan.scanned_bytes
            result = extraction_result(
                source, raw_keys, validated, labels, scan
            )
            result["attempts"] = attempts
            result["accumulated_scanned_bytes"] = accumulated_bytes
            result["accumulated_scanned_human"] = human_size(accumulated_bytes)
            if len(validated) == len(databases):
                if cancel.is_set() or not _capture_update(
                    capture_id,
                    status="finalizing",
                    message="密钥已捕获，正在完成逐库只读验真。",
                ):
                    return
                # Commit the in-memory keyring and completion state atomically.  A
                # simultaneous shutdown/session clear therefore wins cleanly and a
                # stale capture thread cannot repopulate cleared credentials.
                with STATE.guard:
                    if (
                        cancel.is_set()
                        or STATE.capture.get("capture_id") != capture_id
                    ):
                        return
                    STATE.set_raw_keys(source, raw_keys)
                    STATE.capture.update(
                        status="complete",
                        message="所有编辑必需数据库均已通过只读验真。",
                        result=result,
                        completed_at=iso_now(),
                    )
                logging.info(
                    "Config.Cipher capture completed: %s/%s databases in %s attempts",
                    len(validated),
                    len(databases),
                    attempts,
                )
                return
            _capture_update(
                capture_id,
                status="waiting_for_login",
                message=(
                    f"已验真 {len(validated)}/{len(databases)} 个数据库。"
                    "请完成微信登录；若已登录，请打开会话列表和几个聊天。"
                ),
                attempts=attempts,
                validated_database_count=len(validated),
                required_database_count=len(databases),
                candidate_count=len(scan.candidates),
            )
            cancel.wait(2.0)
        if cancel.is_set():
            _capture_update(capture_id, status="cancelled", message="密钥捕获已取消。")
        else:
            _capture_update(
                capture_id,
                status="timed_out",
                message=(
                    f"等待超时，只验真 {len(raw_keys)}/{len(editor_database_paths(source))} "
                    "个数据库。请按“退出微信→登录界面启动捕获→再登录”的顺序重试。"
                ),
            )
    except Exception as exc:
        logging.exception("Key capture worker failed")
        _capture_update(capture_id, status="error", message=str(exc))


def start_key_capture(source_text: str, timeout_seconds: float = 180.0) -> dict[str, Any]:
    source = account_root_from_input(source_text)
    database_key_context(source)
    timeout = max(30.0, min(300.0, float(timeout_seconds)))
    with STATE.guard:
        if STATE.capture_thread is not None and STATE.capture_thread.is_alive():
            raise AppError("已有密钥捕获任务正在运行。")
        STATE.clear_key()
        capture_id = uuid.uuid4().hex
        cancel = threading.Event()
        STATE.capture_cancel = cancel
        STATE.capture = {
            "capture_id": capture_id,
            "status": "waiting_for_weixin",
            "message": "等待微信登录界面。启动捕获后再登录微信。",
            "started_at": iso_now(),
            "timeout_seconds": int(timeout),
            "attempts": 0,
        }
        thread = threading.Thread(
            target=key_capture_worker,
            args=(capture_id, source, cancel, timeout),
            daemon=True,
            name="wechat-key-capture",
        )
        STATE.capture_thread = thread
        thread.start()
        return dict(STATE.capture)


def key_capture_status() -> dict[str, Any]:
    with STATE.guard:
        return json.loads(json.dumps(STATE.capture, ensure_ascii=False))


def cancel_key_capture() -> dict[str, Any]:
    with STATE.guard:
        if STATE.capture_cancel is not None:
            STATE.capture_cancel.set()
        if STATE.capture.get("status") not in {
            "complete",
            "error",
            "timed_out",
            "cancelled",
            "idle",
        }:
            STATE.capture.update(status="cancelled", message="密钥捕获已取消。")
        return dict(STATE.capture)


def unlock_snapshot(key_hex: str) -> dict[str, Any]:
    if not HEX_KEY_RE.fullmatch(key_hex.strip()):
        raise AppError("密钥必须是 64 个十六进制字符。")
    databases = message_database_paths()
    if not databases:
        raise AppError("编辑层中没有聊天分片数据库。")
    key = bytes.fromhex(key_hex.strip())
    try:
        with encrypted_connection(databases[0], key=key) as connection:
            connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            integrity = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
            if integrity != "ok":
                raise AppError(f"数据库快速检查未通过：{integrity}")
    except AppError:
        raise
    except Exception as exc:
        raise AppError("密钥无法打开该快照，请核对密钥与账号目录是否匹配。") from exc
    STATE.set_key(key)
    with STATE.guard:
        STATE.conversations_cache = None
        STATE.contacts_cache = None
    logging.info("Snapshot unlocked: %s", STATE.snapshot_root)
    return {"unlocked": True, "database_count": len(databases)}


def lock_snapshot() -> dict[str, Any]:
    with STATE.guard:
        direct_mode = STATE.mode == "direct"
    if direct_mode:
        STATE.clear_session()
    else:
        STATE.clear_key()
    return {"unlocked": False}


def open_direct_source(
    source_text: str,
    key_hex: str,
    use_extracted_keys: bool = False,
) -> dict[str, Any]:
    """Open the user's live account directory as the write target, without copying it."""
    processes = running_weixin_processes()
    if processes:
        raise AppError(
            "检测到微信仍在运行（"
            + "、".join(processes)
            + "）。直接修改源数据库前必须从微信菜单正常退出。"
        )
    source = account_root_from_input(source_text)
    supplied_key = key_hex.strip()
    if supplied_key.startswith(KEY_BUNDLE_PREFIX):
        import_key_bundle(source, supplied_key)
        use_extracted_keys = True
        key = None
        key_mode = "imported-raw-keyring"
    elif use_extracted_keys:
        if not STATE.extracted_keys_match(source):
            raise AppError("内存密钥环不存在或不属于这个账号目录，请重新提取。")
        key = None
        key_mode = "sqlcipher-raw-keyring"
    else:
        if not HEX_KEY_RE.fullmatch(supplied_key):
            raise AppError(
                "请填写 64 位十六进制账号密钥、WCKEY1 密钥包，或先自动提取。"
            )
        key = bytes.fromhex(supplied_key)
        key_mode = "passphrase"
    message_dir = source / "db_storage" / "message"
    databases = sorted(
        path for path in message_dir.glob("*.db") if MESSAGE_DB_RE.match(path.name)
    )
    if not databases:
        raise AppError("源目录中没有聊天分片数据库。")
    try:
        with encrypted_connection(databases[0], key=key) as connection:
            connection.execute("SELECT COUNT(*) FROM sqlite_master").fetchone()
            integrity = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
            if integrity != "ok":
                raise AppError(f"源数据库快速检查未通过：{integrity}")
    except AppError:
        raise
    except Exception as exc:
        raise AppError("密钥无法打开源数据库，请核对密钥与账号目录。") from exc
    with STATE.guard:
        if not use_extracted_keys:
            STATE.clear_key()
        STATE.snapshot_root = None
        STATE.source_root = source
        STATE.manifest = None
        STATE.mode = "direct"
        STATE.conversations_cache = None
        STATE.contacts_cache = None
    if key is not None:
        STATE.set_key(key)
    logging.info("Direct source opened for editing (%s message databases)", len(databases))
    return {
        "opened": True,
        "mode": "direct",
        "source_root": str(source),
        "database_count": len(databases),
        "key_mode": key_mode,
    }


def direct_status() -> dict[str, Any]:
    with STATE.guard:
        return {
            "mode": STATE.mode,
            "opened": STATE.mode == "direct" and STATE.source_root is not None,
            "unlocked": STATE.mode == "direct" and STATE.unlocked,
            "source_root": str(STATE.source_root) if STATE.source_root else None,
            "extracted_keyring_ready": bool(
                STATE._raw_keys and STATE.extracted_source_root is not None
            ),
            "extracted_source_root": (
                str(STATE.extracted_source_root) if STATE.extracted_source_root else None
            ),
            "extracted_key_count": len(STATE._raw_keys),
            "capture": json.loads(json.dumps(STATE.capture, ensure_ascii=False)),
            "weixin_running": running_weixin_processes(),

        }


def ensure_direct_write_allowed() -> None:
    if STATE.mode != "direct":
        return
    processes = running_weixin_processes()
    if processes:
        raise AppError(
            "检测到微信已经重新启动（"
            + "、".join(processes)
            + "）。为避免并发写坏数据库，本次保存已拒绝；请退出微信后重试。"
        )


def checkpoint_and_verify(connection: Any, schema: str = "main") -> None:
    """Force committed WAL data into a DB (including an attached DB) and verify it."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
        raise AppError("数据库 schema 名称无效。")
    prefix = "" if schema == "main" else f"{schema}."
    checkpoint = connection.execute(f"PRAGMA {prefix}wal_checkpoint(FULL)").fetchone()
    if checkpoint is not None and len(checkpoint) >= 1 and int(checkpoint[0]) != 0:
        raise AppError(f"WAL checkpoint 未完成：{tuple(checkpoint)}")
    result = connection.execute(f"PRAGMA {prefix}quick_check(1)").fetchone()[0]
    if result != "ok":
        raise AppError(f"保存后数据库快速检查未通过：{result}")


def load_contacts() -> dict[str, str]:
    with STATE.guard:
        if STATE.contacts_cache is not None:
            return STATE.contacts_cache
    contacts: dict[str, str] = {}
    path = working_root() / "db_storage" / "contact" / "contact.db"
    if path.is_file():
        try:
            with encrypted_connection(path) as connection:
                for row in connection.execute(
                    "SELECT username, remark, nick_name FROM contact WHERE username IS NOT NULL"
                ):
                    username = str(row["username"] or "")
                    display = str(row["remark"] or row["nick_name"] or username)
                    if username:
                        contacts[username] = display
        except Exception:
            logging.exception("Could not load contact display names")
    with STATE.guard:
        STATE.contacts_cache = contacts
    return contacts


def quote_identifier(value: str) -> str:
    return '"' + value.replace('"', '""') + '"'


def relative_db_path(path: Path) -> str:
    return path.relative_to(working_root()).as_posix()


def list_conversations(*, refresh: bool = False) -> list[dict[str, Any]]:
    with STATE.guard:
        if STATE.conversations_cache is not None and not refresh:
            return STATE.conversations_cache
    contacts = load_contacts()
    result: list[dict[str, Any]] = []
    for database in message_database_paths():
        db_rel = relative_db_path(database)
        try:
            with encrypted_connection(database) as connection:
                existing = {
                    row[0]
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                    )
                }
                names: dict[str, tuple[str, int, int]] = {}
                try:
                    for row in connection.execute(
                        "SELECT rowid AS sender_id, user_name, is_session FROM Name2Id"
                    ):
                        username = str(row["user_name"] or "")
                        suffix = hashlib.md5(username.encode("utf-8")).hexdigest()
                        names[f"Msg_{suffix}".lower()] = (
                            username,
                            int(row["is_session"] or 0),
                            int(row["sender_id"]),
                        )
                except Exception:
                    logging.exception("Name2Id unavailable in %s", database)
                for table in sorted(existing):
                    mapped = names.get(table.lower())
                    username = mapped[0] if mapped else ""
                    is_session = mapped[1] if mapped else 1
                    if not is_session and mapped:
                        continue
                    display = contacts.get(username, username) if username else f"未映射会话 {table[-8:]}"
                    result.append(
                        {
                            "id": f"{db_rel}|{table}",
                            "db_rel": db_rel,
                            "database": database.name,
                            "table": table,
                            "username": username,
                            "display_name": display,
                            "is_group": username.endswith("@chatroom"),
                        }
                    )
        except Exception:
            logging.exception("Could not enumerate conversations in %s", database)
    result.sort(key=lambda item: (item["display_name"].casefold(), item["database"], item["table"]))
    with STATE.guard:
        STATE.conversations_cache = result
    return result


def validate_table(connection: Any, table: str) -> None:
    if not TABLE_RE.fullmatch(table):
        raise AppError("消息表名无效。")
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)
    ).fetchone()
    if row is None:
        raise AppError("消息表不存在。")


def sender_map(connection: Any) -> dict[int, str]:
    try:
        return {
            int(row[0]): str(row[1] or "")
            for row in connection.execute("SELECT rowid, user_name FROM Name2Id")
        }
    except Exception:
        return {}


def decompress_zstd(value: bytes) -> bytes:
    return zstd.ZstdDecompressor().decompress(value, max_output_size=MAX_TEXT_BYTES)


def decode_db_text(value: Any) -> tuple[str, str, bool]:
    if value is None:
        return "", "null", True
    if isinstance(value, str):
        return value, "text", True
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        if value.startswith(ZSTD_MAGIC):
            try:
                data = decompress_zstd(value)
                return data.decode("utf-8", errors="replace"), "zstd", True
            except Exception:
                return f"[无法解压的 Zstandard 数据，{len(value)} 字节]", "zstd-error", False
        try:
            return value.decode("utf-8"), "blob-utf8", True
        except UnicodeDecodeError:
            preview = base64.b64encode(value[:96]).decode("ascii")
            return f"[二进制数据，{len(value)} 字节；Base64 前缀：{preview}]", "blob", False
    return str(value), type(value).__name__, False


GROUP_SENDER_PREFIX_RE = re.compile(r"^(?P<prefix>[^\r\n]{1,256}:\r?\n)")


def split_visible_content(content: str, is_group: bool) -> tuple[str, str]:
    """Separate WeChat's internal group-sender prefix from the text shown in a bubble."""
    if is_group:
        match = GROUP_SENDER_PREFIX_RE.match(content)
        if match:
            return match.group("prefix"), content[match.end() :]
    return "", content


def truncate_utf8(value: str, max_bytes: int) -> str:
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def conversation_username_for_table(connection: Any, table: str) -> str:
    """Resolve Msg_<md5(username)> without trusting a username supplied by the browser."""
    try:
        rows = connection.execute(
            "SELECT user_name FROM Name2Id WHERE is_session=1 AND user_name IS NOT NULL"
        )
    except Exception:
        rows = connection.execute("SELECT user_name FROM Name2Id WHERE user_name IS NOT NULL")
    expected = table.casefold()
    for row in rows:
        username = str(row[0] or "")
        candidate = "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()
        if username and candidate.casefold() == expected:
            return username
    return ""


def session_database_path() -> Path:
    return working_root() / "db_storage" / "session" / "session.db"


def attach_session_database(connection: Any, alias: str = "session_sync") -> bool:
    """Attach session.db with its own credential for one coordinated commit."""
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", alias):
        raise AppError("数据库 schema 名称无效。")
    path = session_database_path()
    if not path.is_file():
        return False
    master_key = STATE.master_key_bytes()
    if master_key is not None:
        connection.execute(
            f'ATTACH DATABASE ? AS "{alias}" KEY ?',
            (str(path), master_key),
        )
    else:
        raw_key = STATE.raw_key_for_path(path)
        salt = encrypted_database_salt(path)
        if salt is None:
            raise AppError("无法读取 session.db 的 SQLCipher salt。")
        raw_literal = raw_key.hex() + salt
        connection.execute(
            f'ATTACH DATABASE ? AS "{alias}" KEY "x\'{raw_literal}\'"',
            (str(path),),
        )
    return True


def sync_last_message_preview(
    connection: Any,
    *,
    schema: str,
    username: str,
    local_id: int,
    message_row: Any,
) -> dict[str, Any]:
    """Update SessionTable.summary only when this record is the session's last text message."""
    result: dict[str, Any] = {
        "session_preview_updated": False,
        "reason": "not_last_message",
        "fts_index_updated": False,
    }
    if not username:
        result["reason"] = "conversation_unmapped"
        return result
    session = connection.execute(
        f'SELECT last_msg_locald_id FROM "{schema}".SessionTable '
        "WHERE username=? AND last_msg_locald_id=?",
        (username, int(local_id)),
    ).fetchone()
    if session is None:
        return result
    local_type = int(message_row["local_type"] or 0) & 0xFFFFFFFF
    if local_type != 1:
        result["reason"] = "last_message_is_not_text"
        return result
    raw_content, _, editable = decode_db_text(message_row["message_content"])
    if not editable:
        result["reason"] = "content_not_decodable"
        return result
    _, visible = split_visible_content(raw_content, username.endswith("@chatroom"))
    summary = truncate_utf8(visible, SESSION_SUMMARY_MAX_BYTES)
    cursor = connection.execute(
        f'UPDATE "{schema}".SessionTable SET summary=? '
        "WHERE username=? AND last_msg_locald_id=?",
        (summary, username, int(local_id)),
    )
    if cursor.rowcount == 1:
        result.update(
            {
                "session_preview_updated": True,
                "reason": "updated",
                "summary_utf8_bytes": len(summary.encode("utf-8")),
            }
        )
    return result


TYPE_LABELS = {
    1: "文本",
    3: "图片",
    34: "语音",
    37: "好友确认",
    42: "名片",
    43: "视频",
    47: "表情",
    48: "位置",
    49: "链接/文件/应用消息",
    10000: "系统消息",
    10002: "撤回消息",
}


def display_timestamp(value: Any) -> str:
    try:
        number = int(value)
        seconds = number / 1000 if number > 10_000_000_000 else number
        return datetime.fromtimestamp(seconds).astimezone().strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(value or "")


def row_to_message(
    row: Any,
    db_rel: str,
    table: str,
    senders: dict[int, str],
    conversation_username: str = "",
) -> dict[str, Any]:
    content, content_storage, content_editable = decode_db_text(row["message_content"])
    content_prefix, display_content = split_visible_content(
        content, conversation_username.endswith("@chatroom")
    )
    source, source_storage, source_editable = decode_db_text(row["source"])
    is_local_inserted = LOCAL_INSERT_SOURCE_MARKER in source
    local_insert_direction = None
    if is_local_inserted:
        local_insert_direction = "other" if "<direction>other</direction>" in source else "self"
    sender_id = int(row["real_sender_id"] or 0)
    local_type = int(row["local_type"] or 0)
    base_type = local_type & 0xFFFFFFFF
    return {
        "db_rel": db_rel,
        "table": table,
        "local_id": int(row["local_id"]),
        "server_id": row["server_id"],
        "local_type": local_type,
        "type_label": TYPE_LABELS.get(local_type, f"类型 {local_type}"),
        "sort_seq": row["sort_seq"],
        "real_sender_id": sender_id,
        "sender_username": senders.get(sender_id, ""),
        "create_time": row["create_time"],
        "display_time": display_timestamp(row["create_time"]),
        "status": row["status"],
        "upload_status": row["upload_status"],
        "download_status": row["download_status"],
        "server_seq": row["server_seq"],
        "origin_source": row["origin_source"],
        "message_content": content,
        "display_content": display_content,
        "content_has_group_prefix": bool(content_prefix),
        "display_content_editable": content_editable and base_type == 1,
        "content_storage": content_storage,
        "content_editable": content_editable,
        "source": source,
        "is_local_inserted": is_local_inserted,
        "local_insert_direction": local_insert_direction,
        "source_storage": source_storage,
        "source_editable": source_editable,
        "compression_content": row["WCDB_CT_message_content"],
        "compression_source": row["WCDB_CT_source"],
    }


MESSAGE_COLUMNS = (
    "local_id, server_id, local_type, sort_seq, real_sender_id, create_time, status, "
    "upload_status, download_status, server_seq, origin_source, source, message_content, "
    "WCDB_CT_message_content, WCDB_CT_source"
)


def list_messages(db_rel: str, table: str, page: int, page_size: int) -> dict[str, Any]:
    database = safe_working_db(db_rel)
    page = max(1, page)
    page_size = max(1, min(200, page_size))
    offset = (page - 1) * page_size
    with encrypted_connection(database) as connection:
        validate_table(connection, table)
        quoted = quote_identifier(table)
        senders = sender_map(connection)
        conversation_username = conversation_username_for_table(connection, table)
        rows = connection.execute(
            f"SELECT {MESSAGE_COLUMNS} FROM {quoted} "
            "ORDER BY sort_seq DESC, local_id DESC LIMIT ? OFFSET ?",
            (page_size + 1, offset),
        ).fetchall()
        count_row = connection.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()
    has_more = len(rows) > page_size
    rows = rows[:page_size]
    return {
        "items": [
            row_to_message(row, db_rel, table, senders, conversation_username) for row in rows
        ],
        "page": page,
        "page_size": page_size,
        "has_more": has_more,
        "total": int(count_row[0]) if count_row else None,
        "senders": [{"id": key, "username": value} for key, value in sorted(senders.items())],
    }


def search_messages(
    keyword: str,
    conversation_id: str | None,
    limit: int,
    scan_limit: int,
) -> dict[str, Any]:
    keyword = keyword.strip()
    if not keyword:
        raise AppError("请输入搜索关键词。")
    limit = max(1, min(500, limit))
    scan_limit = max(1_000, min(500_000, scan_limit))
    conversations = list_conversations()
    if conversation_id:
        conversations = [item for item in conversations if item["id"] == conversation_id]
        if not conversations:
            raise AppError("未找到所选会话。")
    results: list[dict[str, Any]] = []
    scanned = 0
    lower_keyword = keyword.casefold()
    grouped: dict[str, list[dict[str, Any]]] = {}
    for conversation in conversations:
        grouped.setdefault(conversation["db_rel"], []).append(conversation)
    for db_rel, database_conversations in grouped.items():
        if len(results) >= limit or scanned >= scan_limit:
            break
        database = safe_working_db(db_rel)
        with encrypted_connection(database) as connection:
            senders = sender_map(connection)
            for conversation in database_conversations:
                if len(results) >= limit or scanned >= scan_limit:
                    break
                validate_table(connection, conversation["table"])
                quoted = quote_identifier(conversation["table"])
                cursor = connection.execute(
                    f"SELECT {MESSAGE_COLUMNS} FROM {quoted} "
                    "ORDER BY sort_seq DESC, local_id DESC"
                )
                while len(results) < limit and scanned < scan_limit:
                    rows = cursor.fetchmany(500)
                    if not rows:
                        break
                    for row in rows:
                        scanned += 1
                        content, _, _ = decode_db_text(row["message_content"])
                        source, _, _ = decode_db_text(row["source"])
                        if lower_keyword in content.casefold() or lower_keyword in source.casefold():
                            item = row_to_message(
                                row,
                                conversation["db_rel"],
                                conversation["table"],
                                senders,
                                conversation["username"],
                            )
                            item["conversation_id"] = conversation["id"]
                            item["conversation_name"] = conversation["display_name"]
                            item["username"] = conversation["username"]
                            results.append(item)
                            if len(results) >= limit:
                                break
                    if scanned >= scan_limit:
                        break
    return {
        "items": results,
        "scanned": scanned,
        "limit": limit,
        "scan_limit": scan_limit,
        "truncated": scanned >= scan_limit or len(results) >= limit,
    }


def encode_audit_value(value: Any) -> Any:
    if isinstance(value, memoryview):
        value = value.tobytes()
    if isinstance(value, bytes):
        return {"__bytes__": base64.b64encode(value).decode("ascii")}
    return value


def decode_audit_value(value: Any) -> Any:
    if isinstance(value, dict) and set(value) == {"__bytes__"}:
        return base64.b64decode(value["__bytes__"])
    return value


def serialize_row(row: Any) -> str:
    return json.dumps(
        {key: encode_audit_value(row[key]) for key in row.keys()},
        ensure_ascii=False,
        separators=(",", ":"),
    )


def deserialize_row(value: str) -> dict[str, Any]:
    data = json.loads(value)
    return {key: decode_audit_value(item) for key, item in data.items()}


def audit_path() -> Path:
    if STATE.snapshot_root is None:
        raise AppError("尚未打开快照。")
    return STATE.snapshot_root / "editor_audit.db"


@contextmanager
def audit_connection():
    path = audit_path()
    with encrypted_connection(path) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS changes("
            "id INTEGER PRIMARY KEY AUTOINCREMENT, changed_at TEXT NOT NULL, action TEXT NOT NULL, "
            "db_rel TEXT NOT NULL, table_name TEXT NOT NULL, local_id INTEGER NOT NULL, "
            "before_json TEXT NOT NULL, after_json TEXT, status TEXT NOT NULL DEFAULT 'pending', "
            "undone INTEGER NOT NULL DEFAULT 0, error TEXT)"
        )
        connection.commit()
        yield connection


def create_pending_audit(
    action: str,
    db_rel: str,
    table: str,
    local_id: int,
    before_json: str,
    after_json: str | None,
) -> int:
    with audit_connection() as connection:
        cursor = connection.execute(
            "INSERT INTO changes(changed_at,action,db_rel,table_name,local_id,before_json,after_json) "
            "VALUES(?,?,?,?,?,?,?)",
            (iso_now(), action, db_rel, table, local_id, before_json, after_json),
        )
        connection.commit()
        return int(cursor.lastrowid)


def set_audit_status(audit_id: int, status: str, error: str | None = None) -> None:
    with audit_connection() as connection:
        connection.execute(
            "UPDATE changes SET status=?, error=? WHERE id=?", (status, error, audit_id)
        )
        connection.commit()


def encode_edited_text(new_value: str, old_value: Any, compression_flag: Any) -> Any:
    should_compress = False
    if isinstance(old_value, memoryview):
        old_value = old_value.tobytes()
    if isinstance(old_value, bytes) and old_value.startswith(ZSTD_MAGIC):
        should_compress = True
    try:
        should_compress = should_compress or int(compression_flag or 0) != 0
    except Exception:
        pass
    if should_compress:
        return zstd.ZstdCompressor(level=3).compress(new_value.encode("utf-8"))
    if isinstance(old_value, bytes):
        return new_value.encode("utf-8")
    return new_value


NUMERIC_FIELDS = {
    "create_time",
    "local_type",
    "real_sender_id",
    "status",
    "upload_status",
    "download_status",
    "server_seq",
    "origin_source",
    "sort_seq",
}
EDITABLE_FIELDS = NUMERIC_FIELDS | {"message_content", "display_content", "source"}


def resolve_self_sender_for_insert(
    connection: Any, table: str, conversation_username: str
) -> tuple[int, str]:
    """Infer the account's own Name2Id row from existing successfully-sent text."""
    names = sender_map(connection)
    session_rows: list[tuple[str, str, int]] = []
    try:
        rows = connection.execute(
            "SELECT rowid,user_name FROM Name2Id WHERE is_session=1 AND user_name IS NOT NULL"
        )
    except Exception:
        rows = connection.execute(
            "SELECT rowid,user_name FROM Name2Id WHERE user_name IS NOT NULL"
        )
    for row in rows:
        username = str(row[1] or "")
        if not username:
            continue
        session_table = "Msg_" + hashlib.md5(username.encode("utf-8")).hexdigest()
        session_rows.append((session_table, username, int(row[0])))

    target_session_id = next(
        (rowid for name, username, rowid in session_rows if name.casefold() == table.casefold()),
        None,
    )

    def candidate_from(candidate_table: str, candidate_username: str, session_id: int) -> Any:
        if not TABLE_RE.fullmatch(candidate_table):
            return None
        exists = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (candidate_table,)
        ).fetchone()
        if exists is None:
            return None
        quoted = quote_identifier(candidate_table)
        parameters: list[Any] = []
        direction_filter = ""
        if not candidate_username.endswith("@chatroom"):
            direction_filter = " AND real_sender_id<>?"
            parameters.append(session_id)
        return connection.execute(
            f"SELECT real_sender_id FROM {quoted} "
            "WHERE (local_type & 4294967295)=1 AND status=2 AND server_id<>0"
            f"{direction_filter} "
            "ORDER BY CASE WHEN origin_source=6 THEN 0 ELSE 1 END, sort_seq DESC LIMIT 1",
            parameters,
        ).fetchone()

    if target_session_id is not None:
        row = candidate_from(table, conversation_username, target_session_id)
        if row is not None:
            sender_id = int(row[0] or 0)
            sender_username = names.get(sender_id, "")
            if sender_id and sender_username:
                return sender_id, sender_username

    # A conversation with no outgoing text can still use the account identity proven by
    # another private conversation in the same message shard.
    for candidate_table, candidate_username, session_id in session_rows:
        if candidate_username.endswith("@chatroom"):
            continue
        row = candidate_from(candidate_table, candidate_username, session_id)
        if row is None:
            continue
        sender_id = int(row[0] or 0)
        sender_username = names.get(sender_id, "")
        if sender_id and sender_username:
            return sender_id, sender_username

    raise AppError(
        "无法从该分片的既有成功发送记录确认“我”的发送者编号；为避免生成错误身份，本次新增已取消。"
    )


def conversation_session_identity(
    connection: Any, conversation_username: str
) -> tuple[int, str]:
    row = connection.execute(
        "SELECT rowid,user_name FROM Name2Id WHERE user_name=? "
        "ORDER BY CASE WHEN is_session=1 THEN 0 ELSE 1 END LIMIT 1",
        (conversation_username,),
    ).fetchone()
    if row is None or int(row[0] or 0) <= 0:
        raise AppError("无法确认该会话在 Name2Id 中的内部编号，已取消新增。")
    return int(row[0]), str(row[1] or conversation_username)


def encode_protobuf_varint(value: int) -> bytes:
    """Encode one non-negative protobuf varint used by packed_info_data."""
    number = int(value)
    if number <= 0 or number > 0x7FFFFFFFFFFFFFFF:
        raise AppError("消息路由编号超出有效范围。")
    output = bytearray()
    while number >= 0x80:
        output.append((number & 0x7F) | 0x80)
        number >>= 7
    output.append(number)
    return bytes(output)


def build_text_packed_route(source_id: int, target_id: int) -> bytes:
    """Build WeChat's two-varint text route: field 1 source, field 2 target."""
    return (
        b"\x08"
        + encode_protobuf_varint(source_id)
        + b"\x10"
        + encode_protobuf_varint(target_id)
    )


def insert_sender_options_for_connection(
    connection: Any,
    table: str,
    conversation_username: str,
) -> dict[str, Any]:
    """Resolve safe, already-observed identities available to a local insert."""
    self_id, self_username = resolve_self_sender_for_insert(
        connection, table, conversation_username
    )
    session_id, _ = conversation_session_identity(connection, conversation_username)
    is_group = conversation_username.endswith("@chatroom")
    names = sender_map(connection)
    contacts = load_contacts()
    other_senders: list[dict[str, Any]] = []
    if is_group:
        quoted = quote_identifier(table)
        rows = connection.execute(
            f"SELECT real_sender_id,COUNT(*) AS message_count,MAX(sort_seq) AS last_sort_seq "
            f"FROM {quoted} WHERE (local_type & 4294967295)=1 AND status=4 "
            "AND real_sender_id IS NOT NULL AND real_sender_id<>? "
            "GROUP BY real_sender_id ORDER BY last_sort_seq DESC",
            (self_id,),
        )
        for row in rows:
            sender_id = int(row[0] or 0)
            username = names.get(sender_id, "")
            if sender_id <= 0 or not username or username == conversation_username:
                continue
            display_name = contacts.get(username, username)
            other_senders.append(
                {
                    "id": sender_id,
                    "username": username,
                    "display_name": display_name,
                    "message_count": int(row[1] or 0),
                }
            )
    else:
        peer_username = names.get(session_id, conversation_username)
        other_senders.append(
            {
                "id": session_id,
                "username": peer_username,
                "display_name": contacts.get(peer_username, peer_username),
                "message_count": None,
            }
        )
    return {
        "conversation_username": conversation_username,
        "conversation_id": session_id,
        "is_group": is_group,
        "self_sender": {
            "id": self_id,
            "username": self_username,
            "display_name": contacts.get(self_username, self_username),
        },
        "other_senders": other_senders,
    }


def insert_message_options(db_rel: str, table: str) -> dict[str, Any]:
    if STATE.mode != "direct":
        raise AppError("新增本地聊天记录仅支持直接源库模式。")
    database = safe_working_db(db_rel)
    with encrypted_connection(database) as connection:
        validate_table(connection, table)
        conversation_username = conversation_username_for_table(connection, table)
        if not conversation_username:
            raise AppError("无法确认这个消息表对应的会话。")
        return insert_sender_options_for_connection(
            connection, table, conversation_username
        )


def generate_local_server_id(connection: Any, quoted_table: str) -> int:
    """Generate a positive, non-zero local-only ID that cannot look like a pending send."""
    for _ in range(32):
        value = LOCAL_SERVER_ID_PREFIX | secrets.randbits(56)
        exists = connection.execute(
            f"SELECT 1 FROM {quoted_table} WHERE server_id=? LIMIT 1", (value,)
        ).fetchone()
        if exists is None:
            return value
    raise AppError("无法生成不冲突的本地消息标识，请重试。")


def generate_sort_seq(connection: Any, quoted_table: str, create_time: int) -> int:
    base = int(create_time) * 1000
    row = connection.execute(
        f"SELECT MAX(sort_seq) FROM {quoted_table} WHERE sort_seq BETWEEN ? AND ?",
        (base, base + 999),
    ).fetchone()
    if row is None or row[0] is None:
        return base
    value = int(row[0]) + 1
    if value > base + 999:
        raise AppError("所选时间同一秒内已有过多消息，请把时间调整一秒。")
    return value


def sync_session_after_insert(
    connection: Any,
    *,
    schema: str,
    username: str,
    sender_username: str,
    sender_display_name: str,
    local_id: int,
    create_time: int,
    visible_content: str,
    is_latest: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "session_preview_updated": False,
        "reason": "historical_insert" if not is_latest else "session_missing",
        "fts_index_updated": False,
    }
    if not is_latest:
        return result
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", schema):
        raise AppError("数据库 schema 名称无效。")
    exists = connection.execute(
        f'SELECT 1 FROM "{schema}".sqlite_master '
        "WHERE type='table' AND name='SessionTable'"
    ).fetchone()
    if exists is None:
        return result
    session = connection.execute(
        f'SELECT 1 FROM "{schema}".SessionTable WHERE username=?', (username,)
    ).fetchone()
    if session is None:
        return result
    columns = {
        str(row[1])
        for row in connection.execute(f"PRAGMA {schema}.table_info(SessionTable)")
    }
    wanted: dict[str, Any] = {
        "summary": truncate_utf8(visible_content, SESSION_SUMMARY_MAX_BYTES),
        "last_timestamp": int(create_time),
        "sort_timestamp": int(create_time),
        "last_msg_locald_id": int(local_id),
        "last_msg_type": 1,
        "last_msg_sub_type": 0,
        "last_msg_sender": sender_username,
        "last_sender_display_name": sender_display_name,
        "last_msg_ext_type": 0,
    }
    updates = {key: value for key, value in wanted.items() if key in columns}
    if "summary" not in updates or "last_msg_locald_id" not in updates:
        result["reason"] = "session_schema_incompatible"
        return result
    assignments = ", ".join(f"{quote_identifier(key)}=?" for key in updates)
    cursor = connection.execute(
        f'UPDATE "{schema}".SessionTable SET {assignments} WHERE username=?',
        [*updates.values(), username],
    )
    if cursor.rowcount == 1:
        result.update(
            {
                "session_preview_updated": True,
                "reason": "updated",
                "updated_fields": sorted(updates),
            }
        )
    return result


def insert_text_message(
    db_rel: str,
    table: str,
    visible_content: str,
    create_time: Any,
    sender_mode: str = "self",
    sender_id: Any = None,
) -> dict[str, Any]:
    if STATE.mode != "direct":
        raise AppError("新增本地聊天记录仅支持直接源库模式。")
    ensure_direct_write_allowed()
    content = str(visible_content)
    if not content.strip():
        raise AppError("新增聊天正文不能为空。")
    if len(content) > MAX_INSERT_TEXT_CHARS:
        raise AppError(f"新增聊天正文不能超过 {MAX_INSERT_TEXT_CHARS} 个字符。")
    try:
        timestamp = int(create_time)
    except (TypeError, ValueError) as exc:
        raise AppError("消息时间必须是 Unix 秒级时间戳。") from exc
    if timestamp < 946684800 or timestamp > 4102444800:
        raise AppError("消息时间必须在 2000-01-01 到 2100-01-01 之间。")
    direction = str(sender_mode or "self").strip().casefold()
    if direction not in {"self", "other"}:
        raise AppError("消息发送方只能选择“我发送”或“对方发送”。")

    database = safe_working_db(db_rel)
    with MUTATION_LOCK, encrypted_connection(database) as connection:
        validate_table(connection, table)
        quoted = quote_identifier(table)
        conversation_username = conversation_username_for_table(connection, table)
        if not conversation_username:
            raise AppError("无法确认这个消息表对应的会话，已取消新增。")
        identity_options = insert_sender_options_for_connection(
            connection, table, conversation_username
        )
        self_sender = identity_options["self_sender"]
        self_sender_id = int(self_sender["id"])
        conversation_id = int(identity_options["conversation_id"])
        if direction == "self":
            resolved_sender_id = self_sender_id
            sender_username = str(self_sender["username"])
            sender_display_name = ""
            route_source_id = self_sender_id
            route_target_id = conversation_id
            status = 2
            source_value = LOCAL_INSERT_SOURCE
            stored_content = content
        else:
            candidates = {
                int(item["id"]): item for item in identity_options["other_senders"]
            }
            if identity_options["is_group"]:
                try:
                    requested_sender_id = int(sender_id)
                except (TypeError, ValueError) as exc:
                    raise AppError("群聊新增对方消息时必须选择一个已有群成员。") from exc
            else:
                requested_sender_id = conversation_id
                if sender_id not in (None, ""):
                    try:
                        supplied_sender_id = int(sender_id)
                    except (TypeError, ValueError) as exc:
                        raise AppError("对方发送者编号无效。") from exc
                    if supplied_sender_id != conversation_id:
                        raise AppError("私聊只能使用当前会话对方的身份。")
            selected = candidates.get(requested_sender_id)
            if selected is None:
                raise AppError("所选对方身份未在这个会话中出现，已取消新增。")
            resolved_sender_id = int(selected["id"])
            sender_username = str(selected["username"])
            display = str(selected.get("display_name") or "")
            sender_display_name = display if display != sender_username else ""
            route_source_id = conversation_id
            route_target_id = self_sender_id
            status = 4
            source_value = LOCAL_INSERT_OTHER_SOURCE
            stored_content = (
                f"{sender_username}:\n{content}"
                if identity_options["is_group"]
                else content
            )
        packed_route = build_text_packed_route(route_source_id, route_target_id)
        previous_max_row = connection.execute(
            f"SELECT MAX(sort_seq) FROM {quoted}"
        ).fetchone()
        previous_max = int(previous_max_row[0]) if previous_max_row and previous_max_row[0] else -1
        sort_seq = generate_sort_seq(connection, quoted, timestamp)
        server_id = generate_local_server_id(connection, quoted)
        try:
            session_attached = attach_session_database(connection)
        except Exception as exc:
            raise AppError("无法打开 session.db，已取消新增，源消息尚未写入。") from exc
        if not session_attached:
            raise AppError("没有找到 session.db，已取消新增，源消息尚未写入。")
        session_sync: dict[str, Any]
        try:
            cursor = connection.execute(
                f"INSERT INTO {quoted}("
                "server_id,local_type,sort_seq,real_sender_id,create_time,status,"
                "upload_status,download_status,server_seq,origin_source,source,message_content,"
                "compress_content,packed_info_data,WCDB_CT_message_content,WCDB_CT_source"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    server_id,
                    1,
                    sort_seq,
                    resolved_sender_id,
                    timestamp,
                    status,
                    0,
                    0,
                    0,
                    6,
                    source_value,
                    stored_content,
                    None,
                    packed_route,
                    None,
                    None,
                ),
            )
            local_id = int(cursor.lastrowid)
            session_sync = sync_session_after_insert(
                connection,
                schema="session_sync",
                username=conversation_username,
                sender_username=sender_username,
                sender_display_name=sender_display_name,
                local_id=local_id,
                create_time=timestamp,
                visible_content=content,
                is_latest=sort_seq > previous_max,
            )
            connection.commit()
            checkpoint_and_verify(connection)
            checkpoint_and_verify(connection, "session_sync")
        except Exception:
            connection.rollback()
            raise
        senders = sender_map(connection)
        row = connection.execute(
            f"SELECT {MESSAGE_COLUMNS} FROM {quoted} WHERE local_id=?", (local_id,)
        ).fetchone()
        try:
            connection.execute('DETACH DATABASE "session_sync"')
        except Exception:
            logging.exception("Could not detach session.db after a successful direct insert")
    return {
        "inserted": True,
        "local_only": True,
        "sender_mode": direction,
        "sender": {
            "id": resolved_sender_id,
            "username": sender_username,
            "display_name": sender_display_name,
        },
        "message": row_to_message(
            row, db_rel, table, senders, conversation_username
        ),
        "display_sync": session_sync,
    }


def repair_local_insert_routes() -> dict[str, Any]:
    """Repair only this tool's older text inserts that omitted packed routing data."""
    if STATE.mode != "direct":
        raise AppError("修复旧版新增记录仅支持直接源库模式。")
    ensure_direct_write_allowed()
    repaired_rows = 0
    repaired_databases: list[str] = []
    repaired_tables = 0
    with MUTATION_LOCK:
        for database in message_database_paths():
            database_repairs = 0
            with encrypted_connection(database) as connection:
                tables = [
                    str(row[0])
                    for row in connection.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'Msg_%'"
                    )
                    if TABLE_RE.fullmatch(str(row[0]))
                ]
                for table in tables:
                    quoted = quote_identifier(table)
                    rows = connection.execute(
                        f"SELECT local_id,real_sender_id,source FROM {quoted} "
                        "WHERE (local_type & 4294967295)=1 "
                        "AND source LIKE ? "
                        "AND (packed_info_data IS NULL OR length(packed_info_data)=0)",
                        (f"%{LOCAL_INSERT_SOURCE_MARKER}%",),
                    ).fetchall()
                    if not rows:
                        continue
                    conversation_username = conversation_username_for_table(
                        connection, table
                    )
                    if not conversation_username:
                        raise AppError(
                            f"无法确认 {database.name}/{table} 对应会话，修复已停止。"
                        )
                    self_id, _ = resolve_self_sender_for_insert(
                        connection, table, conversation_username
                    )
                    conversation_id, _ = conversation_session_identity(
                        connection, conversation_username
                    )
                    table_repairs = 0
                    for row in rows:
                        source_value = str(row["source"] or "")
                        is_other = "<direction>other</direction>" in source_value
                        if is_other:
                            resolved_sender_id = int(row["real_sender_id"] or 0)
                            if resolved_sender_id <= 0 or resolved_sender_id == self_id:
                                raise AppError(
                                    f"{database.name}/{table} 中存在无法确认对方身份的本地记录。"
                                )
                            route = build_text_packed_route(conversation_id, self_id)
                            status = 4
                        else:
                            resolved_sender_id = self_id
                            route = build_text_packed_route(self_id, conversation_id)
                            status = 2
                            if "<direction>self</direction>" not in source_value:
                                if "</msgsource>" in source_value:
                                    source_value = source_value.replace(
                                        "</msgsource>",
                                        "<direction>self</direction></msgsource>",
                                        1,
                                    )
                                else:
                                    source_value = LOCAL_INSERT_SOURCE
                        cursor = connection.execute(
                            f"UPDATE {quoted} SET real_sender_id=?,status=?,origin_source=6,"
                            "packed_info_data=?,source=? WHERE local_id=?",
                            (
                                resolved_sender_id,
                                status,
                                route,
                                source_value,
                                int(row["local_id"]),
                            ),
                        )
                        table_repairs += int(cursor.rowcount or 0)
                    if table_repairs:
                        repaired_tables += 1
                        database_repairs += table_repairs
                if database_repairs:
                    connection.commit()
                    checkpoint_and_verify(connection)
                    repaired_rows += database_repairs
                    repaired_databases.append(relative_db_path(database))
    with STATE.guard:
        STATE.conversations_cache = None
    return {
        "repaired": True,
        "row_count": repaired_rows,
        "table_count": repaired_tables,
        "database_count": len(repaired_databases),
        "databases": repaired_databases,
        "scope": "local-insert-marker-and-missing-packed-route-only",
    }


def update_message(db_rel: str, table: str, local_id: int, fields: dict[str, Any]) -> dict[str, Any]:
    unknown = set(fields) - EDITABLE_FIELDS
    if unknown:
        raise AppError("包含不允许修改的字段：" + "、".join(sorted(unknown)))
    if not fields:
        raise AppError("没有需要保存的修改。")
    if "message_content" in fields and "display_content" in fields:
        raise AppError("不能同时提交原始正文和聊天显示正文。")
    ensure_direct_write_allowed()
    database = safe_working_db(db_rel)
    with MUTATION_LOCK, encrypted_connection(database) as connection:
        validate_table(connection, table)
        quoted = quote_identifier(table)
        old = connection.execute(
            f"SELECT * FROM {quoted} WHERE local_id=?", (int(local_id),)
        ).fetchone()
        if old is None:
            raise AppError("目标消息不存在，可能已被删除。")
        old_dict = {key: old[key] for key in old.keys()}
        conversation_username = conversation_username_for_table(connection, table)
        is_group = conversation_username.endswith("@chatroom")
        converted: dict[str, Any] = {}
        for field, value in fields.items():
            if field in NUMERIC_FIELDS:
                try:
                    converted[field] = int(value)
                except (TypeError, ValueError) as exc:
                    raise AppError(f"字段 {field} 必须是整数。") from exc
            elif field == "message_content":
                converted[field] = encode_edited_text(
                    str(value), old_dict.get(field), old_dict.get("WCDB_CT_message_content")
                )
            elif field == "display_content":
                old_content, _, editable = decode_db_text(old_dict.get("message_content"))
                if not editable:
                    raise AppError("这条消息的正文无法安全解码，不能修改显示文字。")
                prefix, _ = split_visible_content(old_content, is_group)
                converted["message_content"] = encode_edited_text(
                    prefix + str(value),
                    old_dict.get("message_content"),
                    old_dict.get("WCDB_CT_message_content"),
                )
            elif field == "source":
                converted[field] = encode_edited_text(
                    str(value), old_dict.get(field), old_dict.get("WCDB_CT_source")
                )
        direct = STATE.mode == "direct"
        session_attached = False
        display_sync: dict[str, Any] = {
            "session_preview_updated": False,
            "reason": "snapshot_mode" if not direct else "session_db_missing",
            "fts_index_updated": False,
        }
        if direct:
            try:
                session_attached = attach_session_database(connection)
            except Exception as exc:
                raise AppError("无法打开 session.db，已取消保存，源消息尚未修改。") from exc
        audit_id: int | None = None
        if not direct:
            after_dict = dict(old_dict)
            after_dict.update(converted)
            audit_id = create_pending_audit(
                "update",
                db_rel,
                table,
                int(local_id),
                serialize_row(old),
                json.dumps(
                    {key: encode_audit_value(value) for key, value in after_dict.items()},
                    ensure_ascii=False,
                    separators=(",", ":"),
                ),
            )
        try:
            assignments = ", ".join(f"{quote_identifier(key)}=?" for key in converted)
            values = list(converted.values()) + [int(local_id)]
            cursor = connection.execute(
                f"UPDATE {quoted} SET {assignments} WHERE local_id=?", values
            )
            if cursor.rowcount != 1:
                raise AppError("没有更新到目标消息。")
            new_full_row = connection.execute(
                f"SELECT * FROM {quoted} WHERE local_id=?", (int(local_id),)
            ).fetchone()
            if direct and session_attached:
                display_sync = sync_last_message_preview(
                    connection,
                    schema="session_sync",
                    username=conversation_username,
                    local_id=int(local_id),
                    message_row=new_full_row,
                )
            connection.commit()
            if direct:
                checkpoint_and_verify(connection)
                if session_attached:
                    checkpoint_and_verify(connection, "session_sync")
        except Exception as exc:
            connection.rollback()
            if audit_id is not None:
                set_audit_status(audit_id, "failed", str(exc))
            raise
        if audit_id is not None:
            set_audit_status(audit_id, "applied")
        senders = sender_map(connection)
        new_row = connection.execute(
            f"SELECT {MESSAGE_COLUMNS} FROM {quoted} WHERE local_id=?", (int(local_id),)
        ).fetchone()
        if session_attached:
            try:
                connection.execute('DETACH DATABASE "session_sync"')
            except Exception:
                logging.exception("Could not detach session.db after a successful direct update")
    return {
        "audit_id": audit_id,
        "message": row_to_message(
            new_row, db_rel, table, senders, conversation_username
        ),
        "display_sync": display_sync,
    }


def delete_message(db_rel: str, table: str, local_id: int) -> dict[str, Any]:
    ensure_direct_write_allowed()
    if STATE.mode == "direct":
        raise AppError(
            "直接版当前只提供内容修改，不执行源记录删除；删除还需要重算最后一条消息元数据。"
        )
    database = safe_working_db(db_rel)
    with MUTATION_LOCK, encrypted_connection(database) as connection:
        validate_table(connection, table)
        quoted = quote_identifier(table)
        old = connection.execute(
            f"SELECT * FROM {quoted} WHERE local_id=?", (int(local_id),)
        ).fetchone()
        if old is None:
            raise AppError("目标消息不存在，可能已被删除。")
        direct = STATE.mode == "direct"
        audit_id: int | None = None
        if not direct:
            audit_id = create_pending_audit(
                "delete", db_rel, table, int(local_id), serialize_row(old), None
            )
        try:
            cursor = connection.execute(
                f"DELETE FROM {quoted} WHERE local_id=?", (int(local_id),)
            )
            if cursor.rowcount != 1:
                raise AppError("没有删除到目标消息。")
            connection.commit()
            if direct:
                checkpoint_and_verify(connection)
        except Exception as exc:
            connection.rollback()
            if audit_id is not None:
                set_audit_status(audit_id, "failed", str(exc))
            raise
        if audit_id is not None:
            set_audit_status(audit_id, "applied")
    return {"audit_id": audit_id, "deleted": True}


def audit_preview(row_json: str | None) -> str:
    if not row_json:
        return ""
    try:
        row = deserialize_row(row_json)
        content, _, _ = decode_db_text(row.get("message_content"))
        return content[:160]
    except Exception:
        return "[审计内容无法预览]"


def list_audits(limit: int = 100) -> list[dict[str, Any]]:
    if not audit_path().exists():
        return []
    limit = max(1, min(500, limit))
    with audit_connection() as connection:
        rows = connection.execute(
            "SELECT id,changed_at,action,db_rel,table_name,local_id,before_json,after_json,"
            "status,undone,error FROM changes ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [
        {
            "id": int(row["id"]),
            "changed_at": row["changed_at"],
            "action": row["action"],
            "db_rel": row["db_rel"],
            "table": row["table_name"],
            "local_id": row["local_id"],
            "before_preview": audit_preview(row["before_json"]),
            "after_preview": audit_preview(row["after_json"]),
            "status": row["status"],
            "undone": bool(row["undone"]),
            "error": row["error"],
        }
        for row in rows
    ]


def undo_audit(audit_id: int) -> dict[str, Any]:
    with MUTATION_LOCK, audit_connection() as audit:
        latest = audit.execute(
            "SELECT * FROM changes WHERE status='applied' AND undone=0 "
            "AND action IN ('update','delete') ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if latest is None:
            raise AppError("没有可撤销的修改。")
        if int(latest["id"]) != int(audit_id):
            raise AppError("只能按时间倒序撤销，请先撤销更新的操作。")
        before = deserialize_row(latest["before_json"])
        database = safe_working_db(latest["db_rel"])
        table = latest["table_name"]
        with encrypted_connection(database) as connection:
            validate_table(connection, table)
            quoted = quote_identifier(table)
            if latest["action"] == "delete":
                exists = connection.execute(
                    f"SELECT 1 FROM {quoted} WHERE local_id=?", (int(latest["local_id"]),)
                ).fetchone()
                if exists:
                    raise AppError("该 local_id 已存在，无法安全恢复删除记录。")
                columns = list(before)
                names = ",".join(quote_identifier(name) for name in columns)
                placeholders = ",".join("?" for _ in columns)
                connection.execute(
                    f"INSERT INTO {quoted}({names}) VALUES({placeholders})",
                    [before[name] for name in columns],
                )
            else:
                columns = [name for name in before if name != "local_id"]
                assignments = ",".join(f"{quote_identifier(name)}=?" for name in columns)
                cursor = connection.execute(
                    f"UPDATE {quoted} SET {assignments} WHERE local_id=?",
                    [before[name] for name in columns] + [int(latest["local_id"])],
                )
                if cursor.rowcount != 1:
                    raise AppError("目标消息已经不存在，无法撤销更新。")
            connection.commit()
        audit.execute("UPDATE changes SET undone=1 WHERE id=?", (int(audit_id),))
        audit.commit()
    return {"undone": True, "audit_id": int(audit_id)}


def verify_snapshot() -> dict[str, Any]:
    if STATE.manifest is None or STATE.snapshot_root is None:
        raise AppError("尚未打开快照。")
    raw_root = STATE.snapshot_root / STATE.manifest.get("original_encrypted", "original_encrypted")
    checked = 0
    failures: list[dict[str, str]] = []
    for record in STATE.manifest.get("files", []):
        path = raw_root / Path(record["relative"].replace("/", os.sep))
        try:
            digest = hash_file(path)
            if digest != record["sha256"]:
                failures.append({"file": record["relative"], "error": "SHA-256 不匹配"})
            checked += 1
        except Exception as exc:
            failures.append({"file": record["relative"], "error": str(exc)})
    return {"checked": checked, "failures": failures, "ok": not failures}


def quick_check_databases() -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    for database in message_database_paths():
        try:
            with encrypted_connection(database) as connection:
                value = connection.execute("PRAGMA quick_check(1)").fetchone()[0]
            results.append({"database": database.name, "result": value, "ok": value == "ok"})
        except Exception as exc:
            results.append({"database": database.name, "result": str(exc), "ok": False})
    return {"items": results, "ok": all(item["ok"] for item in results)}


def scan_source(source_text: str) -> dict[str, Any]:
    source = account_root_from_input(source_text)
    files = source_candidates(source)
    total = sum(path.stat().st_size for path in files)
    message_databases = [
        path.relative_to(source).as_posix()
        for path in files
        if MESSAGE_DB_RE.match(path.name) and path.suffix.lower() == ".db"
    ]
    return {
        "source": str(source),
        "file_count": len(files),
        "total_bytes": total,
        "total_human": human_size(total),
        "message_databases": message_databases,
        "weixin_running": running_weixin_processes(),
    }


def api_status() -> dict[str, Any]:
    return {
        "app_name": APP_NAME,
        "version": APP_VERSION,
        "default_source": "",
        "suggested_snapshot": "",
        "snapshot": snapshot_summary(),
        "weixin_running": running_weixin_processes(),

    }


class RequestHandler(BaseHTTPRequestHandler):
    server_version = "WeChatCopyEditor/1.0"

    def log_message(self, format_string: str, *args: Any) -> None:
        # Do not persist the loopback session token or query values in the log.
        logging.info("HTTP %s %s", self.command, urlparse(self.path).path)

    def end_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'",
        )
        super().end_headers()

    def send_json(self, value: Any, status: int = HTTPStatus.OK) -> None:
        payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def send_error_json(self, message: str, status: int) -> None:
        self.send_json({"ok": False, "error": message}, status)

    def authorized(self) -> bool:
        parsed = urlparse(self.path)
        query_token = parse_qs(parsed.query).get("token", [""])[0]
        header_token = self.headers.get("X-App-Token", "")
        return secrets.compare_digest(query_token or header_token, SESSION_TOKEN)

    def require_authorized(self) -> None:
        if not self.authorized():
            raise AppError("本地会话令牌无效，请从程序重新打开界面。", HTTPStatus.FORBIDDEN)

    def read_json(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError as exc:
            raise AppError("请求长度无效。") from exc
        if length <= 0 or length > MAX_REQUEST_BYTES:
            raise AppError("请求内容为空或过大。")
        try:
            value = json.loads(self.rfile.read(length).decode("utf-8"))
        except Exception as exc:
            raise AppError("请求 JSON 无法解析。") from exc
        if not isinstance(value, dict):
            raise AppError("请求内容必须是 JSON 对象。")
        return value

    def serve_static(self, path: str) -> None:
        relative = DEFAULT_PAGE if path in ("", "/") else unquote(path.lstrip("/"))
        candidate = (STATIC_DIR / relative).resolve(strict=False)
        if not candidate.is_relative_to(STATIC_DIR.resolve()) or not candidate.is_file():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        payload = candidate.read_bytes()
        content_type = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type in ("application/javascript", "application/json"):
            content_type += "; charset=utf-8"
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            if not parsed.path.startswith("/api/"):
                self.serve_static(parsed.path)
                return
            self.require_authorized()
            query = parse_qs(parsed.query)
            if parsed.path == "/api/status":
                data = api_status()
            elif parsed.path == "/api/direct/status":
                data = direct_status()
            elif parsed.path == "/api/key/capture/status":
                data = key_capture_status()
            elif parsed.path.startswith("/api/jobs/"):
                job_id = parsed.path.rsplit("/", 1)[-1]
                with STATE.guard:
                    job = STATE.jobs.get(job_id)
                    if job is None:
                        raise AppError("任务不存在。", HTTPStatus.NOT_FOUND)
                    data = dict(job)
            elif parsed.path == "/api/conversations":
                refresh = query.get("refresh", ["0"])[0] == "1"
                data = {"items": list_conversations(refresh=refresh)}
            elif parsed.path == "/api/messages":
                data = list_messages(
                    query.get("db_rel", [""])[0],
                    query.get("table", [""])[0],
                    int(query.get("page", ["1"])[0]),
                    int(query.get("page_size", ["80"])[0]),
                )
            elif parsed.path == "/api/audit":
                data = {"items": list_audits(int(query.get("limit", ["100"])[0]))}
            else:
                raise AppError("接口不存在。", HTTPStatus.NOT_FOUND)
            self.send_json({"ok": True, "data": data})
        except AppError as exc:
            self.send_error_json(str(exc), exc.status)
        except Exception:
            logging.exception("GET request failed: %s", urlparse(self.path).path)
            self.send_error_json("程序内部错误，请查看日志。", HTTPStatus.INTERNAL_SERVER_ERROR)

    def do_POST(self) -> None:  # noqa: N802
        try:
            parsed = urlparse(self.path)
            self.require_authorized()
            payload = self.read_json()
            if parsed.path == "/api/source/scan":
                data = scan_source(str(payload.get("source", "")))
            elif parsed.path == "/api/key/extract":
                data = extract_database_key(str(payload.get("source", "")))
            elif parsed.path == "/api/key/capture/start":
                data = start_key_capture(
                    str(payload.get("source", "")),
                    float(payload.get("timeout_seconds", 180)),
                )
            elif parsed.path == "/api/key/capture/cancel":
                data = cancel_key_capture()
            elif parsed.path == "/api/key/export":
                data = export_key_bundle()
            elif parsed.path == "/api/direct/open":
                data = open_direct_source(
                    str(payload.get("source", "")),
                    str(payload.get("key", "")),
                    bool(payload.get("use_extracted_keys", False)),
                )
            elif parsed.path == "/api/direct/lock":
                data = lock_snapshot()
            elif parsed.path == "/api/snapshot/create":
                data = start_snapshot(
                    str(payload.get("source", "")), str(payload.get("target", ""))
                )
            elif parsed.path == "/api/snapshot/open":
                data = load_snapshot(str(payload.get("path", "")))
            elif parsed.path == "/api/snapshot/unlock":
                data = unlock_snapshot(str(payload.get("key", "")))
            elif parsed.path == "/api/snapshot/lock":
                data = lock_snapshot()
            elif parsed.path == "/api/search":
                data = search_messages(
                    str(payload.get("keyword", "")),
                    str(payload["conversation_id"]) if payload.get("conversation_id") else None,
                    int(payload.get("limit", 200)),
                    int(payload.get("scan_limit", 100_000)),
                )
            elif parsed.path == "/api/message/update":
                fields = payload.get("fields")
                if not isinstance(fields, dict):
                    raise AppError("fields 必须是对象。")
                data = update_message(
                    str(payload.get("db_rel", "")),
                    str(payload.get("table", "")),
                    int(payload.get("local_id")),
                    fields,
                )
            elif parsed.path == "/api/message/insert/options":
                data = insert_message_options(
                    str(payload.get("db_rel", "")),
                    str(payload.get("table", "")),
                )
            elif parsed.path == "/api/message/insert/repair-routes":
                data = repair_local_insert_routes()
            elif parsed.path == "/api/message/insert":
                data = insert_text_message(
                    str(payload.get("db_rel", "")),
                    str(payload.get("table", "")),
                    str(payload.get("visible_content", "")),
                    payload.get("create_time"),
                    str(payload.get("sender_mode", "self")),
                    payload.get("sender_id"),
                )
            elif parsed.path == "/api/message/delete":
                data = delete_message(
                    str(payload.get("db_rel", "")),
                    str(payload.get("table", "")),
                    int(payload.get("local_id")),
                )
            elif parsed.path == "/api/audit/undo":
                data = undo_audit(int(payload.get("audit_id")))
            elif parsed.path == "/api/verify/raw":
                data = verify_snapshot()
            elif parsed.path == "/api/verify/databases":
                data = quick_check_databases()
            elif parsed.path == "/api/shutdown":
                data = {"shutting_down": True}
                self.send_json({"ok": True, "data": data})
                STATE.clear_session()
                if SERVER is not None:
                    threading.Thread(target=SERVER.shutdown, daemon=True).start()
                return
            else:
                raise AppError("接口不存在。", HTTPStatus.NOT_FOUND)
            self.send_json({"ok": True, "data": data})
        except AppError as exc:
            self.send_error_json(str(exc), exc.status)
        except Exception:
            logging.exception(
                "POST request failed: %s\n%s",
                urlparse(self.path).path,
                traceback.format_exc(),
            )
            self.send_error_json("程序内部错误，请查看日志。", HTTPStatus.INTERNAL_SERVER_ERROR)


def packaged_self_test() -> int:
    """Fast dependency/runtime check used after building the Windows executable."""
    required_static = ("index.html", "app.js", "direct.html", "direct.js", "style.css")
    if any(not (STATIC_DIR / name).is_file() for name in required_static):
        return 11
    if zstd.ZstdDecompressor().decompress(
        zstd.ZstdCompressor(level=1).compress(b"copy-editor-self-test")
    ) != b"copy-editor-self-test":
        return 12
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "self-test.db"
        key = bytes.fromhex("22" * 32)
        with encrypted_connection(path, key=key) as connection:
            connection.execute("CREATE TABLE sample(value TEXT)")
            connection.execute("INSERT INTO sample VALUES('ok')")
            connection.commit()
        with encrypted_connection(path, key=key) as connection:
            if connection.execute("SELECT value FROM sample").fetchone()[0] != "ok":
                return 13
            if connection.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                return 14
    salt = "33" * 16
    literal = f"x'{key.hex()}{salt}'".encode("ascii")
    if key_extract.find_key_literals(literal, {salt}) != [(key.hex(), salt)]:
        return 15
    if build_text_packed_route(2, 40) != bytes.fromhex("08021028"):
        return 16
    return 0


def main(*, open_browser: bool = True) -> int:
    global SERVER
    setup_logging()
    STATE.clear_session()
    if not STATIC_DIR.is_dir():
        raise RuntimeError(f"Static directory missing: {STATIC_DIR}")
    SERVER = ThreadingHTTPServer(("127.0.0.1", 0), RequestHandler)
    port = SERVER.server_address[1]
    url = f"http://127.0.0.1:{port}/?token={SESSION_TOKEN}"
    logging.info("Application started on loopback port %s", port)
    if not open_browser:
        print(url, flush=True)
    if open_browser:
        threading.Timer(0.4, lambda: webbrowser.open(url, new=1)).start()
    try:
        SERVER.serve_forever(poll_interval=0.25)
    except KeyboardInterrupt:
        pass
    finally:
        STATE.clear_session()
        SERVER.server_close()
        logging.info("Application stopped")
    return 0


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(packaged_self_test())
    raise SystemExit(main(open_browser="--no-browser" not in sys.argv))
