from __future__ import annotations

import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import zstandard as zstd
from sqlcipher3 import dbapi2 as sqlcipher

import app


KEY_HEX = "22" * 32
GROUP = "synthetic-room@chatroom"
SENDER = "wxid_synthetic_sender"
SELF = "wxid_synthetic_self"
TABLE = "Msg_" + hashlib.md5(GROUP.encode("utf-8")).hexdigest()
PEER = "wxid_synthetic_peer"
PRIVATE_TABLE = "Msg_" + hashlib.md5(PEER.encode("utf-8")).hexdigest()


def connect(path: Path):
    connection = sqlcipher.connect(str(path))
    connection.set_key(bytes.fromhex(KEY_HEX))
    connection.row_factory = sqlcipher.Row
    return connection


def create_message_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(path)
    connection.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER)")
    connection.execute("INSERT INTO Name2Id(user_name,is_session) VALUES(?,1)", (GROUP,))
    connection.execute("INSERT INTO Name2Id(user_name,is_session) VALUES(?,0)", (SENDER,))
    connection.execute("INSERT INTO Name2Id(user_name,is_session) VALUES(?,0)", (SELF,))
    sender_id = connection.execute(
        "SELECT rowid FROM Name2Id WHERE user_name=?", (SENDER,)
    ).fetchone()[0]
    self_id = connection.execute(
        "SELECT rowid FROM Name2Id WHERE user_name=?", (SELF,)
    ).fetchone()[0]
    connection.execute(
        f'CREATE TABLE "{TABLE}"('
        "local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, local_type INTEGER, "
        "sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, status INTEGER, "
        "upload_status INTEGER, download_status INTEGER, server_seq INTEGER, origin_source INTEGER, "
        "source TEXT, message_content TEXT, compress_content TEXT, packed_info_data BLOB, "
        "WCDB_CT_message_content INTEGER DEFAULT NULL, WCDB_CT_source INTEGER DEFAULT NULL)"
    )
    connection.execute(
        f'INSERT INTO "{TABLE}"(server_id,local_type,sort_seq,real_sender_id,create_time,status,'
        "upload_status,download_status,server_seq,origin_source,source,message_content,"
        "WCDB_CT_message_content,WCDB_CT_source) VALUES(1,1,1700000000000,?,1700000000,2,0,0,0,6,?,?,NULL,NULL)",
        (self_id, "<msgsource />", "我发过的较早消息"),
    )
    compressed = zstd.ZstdCompressor(level=3).compress(
        f"{SENDER}:\n原始最后一条".encode("utf-8")
    )
    connection.execute(
        f'INSERT INTO "{TABLE}"(server_id,local_type,sort_seq,real_sender_id,create_time,status,'
        "upload_status,download_status,server_seq,origin_source,source,message_content,"
        "WCDB_CT_message_content,WCDB_CT_source) VALUES(2,1,1700000001000,?,1700000001,4,0,0,1,6,?,?,4,NULL)",
        (sender_id, "<msgsource />", compressed),
    )
    connection.commit()
    connection.close()


def create_session_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(path)
    connection.execute(
        "CREATE TABLE SessionTable("
        "username TEXT PRIMARY KEY, type INTEGER, unread_count INTEGER, summary TEXT, "
        "status INTEGER, last_timestamp INTEGER, sort_timestamp INTEGER, "
        "last_msg_locald_id INTEGER, last_msg_type INTEGER, last_msg_sub_type INTEGER, "
        "last_msg_sender TEXT, last_sender_display_name TEXT, last_msg_ext_type INTEGER)"
    )
    connection.execute(
        "INSERT INTO SessionTable(username,type,unread_count,summary,status,last_timestamp,"
        "sort_timestamp,last_msg_locald_id,last_msg_type,last_msg_sub_type,last_msg_sender,"
        "last_sender_display_name,last_msg_ext_type) VALUES(?,0,0,?,0,1700000001,1700000001,"
        "2,1,0,?,?,0)",
        (GROUP, "原始最后一条", SENDER, "测试发送者"),
    )
    connection.commit()
    connection.close()


def create_contact_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = connect(path)
    connection.execute("CREATE TABLE contact(username TEXT, remark TEXT, nick_name TEXT)")
    connection.execute(
        "INSERT INTO contact(username,remark,nick_name) VALUES(?,?,?)",
        (GROUP, "合成测试群", "合成测试群"),
    )
    connection.commit()
    connection.close()


def add_private_conversation(message_path: Path, session_path: Path) -> tuple[int, int]:
    with connect(message_path) as connection:
        connection.execute(
            "INSERT INTO Name2Id(user_name,is_session) VALUES(?,1)", (PEER,)
        )
        peer_id = int(
            connection.execute(
                "SELECT rowid FROM Name2Id WHERE user_name=?", (PEER,)
            ).fetchone()[0]
        )
        self_id = int(
            connection.execute(
                "SELECT rowid FROM Name2Id WHERE user_name=?", (SELF,)
            ).fetchone()[0]
        )
        connection.execute(
            f'CREATE TABLE "{PRIVATE_TABLE}"('
            "local_id INTEGER PRIMARY KEY AUTOINCREMENT, server_id INTEGER, local_type INTEGER, "
            "sort_seq INTEGER, real_sender_id INTEGER, create_time INTEGER, status INTEGER, "
            "upload_status INTEGER, download_status INTEGER, server_seq INTEGER, origin_source INTEGER, "
            "source TEXT, message_content TEXT, compress_content TEXT, packed_info_data BLOB, "
            "WCDB_CT_message_content INTEGER DEFAULT NULL, WCDB_CT_source INTEGER DEFAULT NULL)"
        )
        connection.execute(
            f'INSERT INTO "{PRIVATE_TABLE}"(server_id,local_type,sort_seq,real_sender_id,'
            "create_time,status,upload_status,download_status,server_seq,origin_source,source,"
            "message_content,packed_info_data) VALUES(11,1,1700000000000,?,1700000000,2,0,0,0,6,?,?,?)",
            (
                self_id,
                "<msgsource />",
                "已有本人私聊文本",
                app.build_text_packed_route(self_id, peer_id),
            ),
        )
        connection.commit()
    with connect(session_path) as connection:
        connection.execute(
            "INSERT INTO SessionTable(username,type,unread_count,summary,status,last_timestamp,"
            "sort_timestamp,last_msg_locald_id,last_msg_type,last_msg_sub_type,last_msg_sender,"
            "last_sender_display_name,last_msg_ext_type) VALUES(?,0,0,?,0,1700000000,1700000000,"
            "1,1,0,?,?,0)",
            (PEER, "已有本人私聊文本", SELF, ""),
        )
        connection.commit()
    return peer_id, self_id


class DirectWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        app.STATE.clear_session()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "account"
        self.message_db = self.source / "db_storage" / "message" / "message_0.db"
        self.session_db = self.source / "db_storage" / "session" / "session.db"
        self.contact_db = self.source / "db_storage" / "contact" / "contact.db"
        create_message_database(self.message_db)
        create_session_database(self.session_db)
        create_contact_database(self.contact_db)
        self.original_process_probe = app.running_weixin_processes
        app.running_weixin_processes = lambda: []

    def tearDown(self) -> None:
        app.running_weixin_processes = self.original_process_probe
        app.STATE.clear_session()
        self.temporary.cleanup()

    def raw_keyring(self) -> dict[str, bytes]:
        values = {}
        for path in (self.message_db, self.session_db, self.contact_db):
            salt = app.encrypted_database_salt(path)
            assert salt is not None
            values[salt] = hashlib.pbkdf2_hmac(
                "sha512", bytes.fromhex(KEY_HEX), bytes.fromhex(salt), 256_000, 32
            )
        return values

    def test_direct_update_changes_source_and_syncs_last_message_preview(self) -> None:
        opened = app.open_direct_source(str(self.source), KEY_HEX)
        self.assertEqual(opened["mode"], "direct")
        self.assertEqual(app.working_root(), self.source.resolve())
        conversation = app.list_conversations()[0]
        listing = app.list_messages(conversation["db_rel"], TABLE, 1, 20)
        latest = listing["items"][0]
        older = listing["items"][1]
        self.assertEqual(latest["display_content"], "原始最后一条")
        self.assertTrue(latest["content_has_group_prefix"])
        self.assertEqual(latest["content_storage"], "zstd")

        new_visible = "新内容" * 100
        result = app.update_message(
            latest["db_rel"],
            latest["table"],
            latest["local_id"],
            {"display_content": new_visible},
        )
        self.assertTrue(result["display_sync"]["session_preview_updated"])
        self.assertFalse(result["display_sync"]["fts_index_updated"])

        with connect(self.message_db) as connection:
            row = connection.execute(
                f'SELECT message_content,WCDB_CT_message_content FROM "{TABLE}" WHERE local_id=2'
            ).fetchone()
            raw = bytes(row["message_content"])
            decoded = zstd.ZstdDecompressor().decompress(raw).decode("utf-8")
            self.assertEqual(decoded, f"{SENDER}:\n{new_visible}")
            self.assertEqual(row["WCDB_CT_message_content"], 4)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

        with connect(self.session_db) as connection:
            summary = connection.execute(
                "SELECT summary FROM SessionTable WHERE username=?", (GROUP,)
            ).fetchone()[0]
            self.assertLessEqual(len(summary.encode("utf-8")), 200)
            self.assertTrue(new_visible.startswith(summary))
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

        previous_summary = summary
        older_result = app.update_message(
            older["db_rel"],
            older["table"],
            older["local_id"],
            {"display_content": "修改较早消息"},
        )
        self.assertFalse(older_result["display_sync"]["session_preview_updated"])
        with connect(self.session_db) as connection:
            self.assertEqual(
                connection.execute(
                    "SELECT summary FROM SessionTable WHERE username=?", (GROUP,)
                ).fetchone()[0],
                previous_summary,
            )

        self.assertFalse((self.source / "editor_audit.db").exists())
        self.assertFalse(any(self.root.glob("*snapshot*")))
        with self.assertRaises(app.AppError):
            app.delete_message(older["db_rel"], older["table"], older["local_id"])

    def test_direct_open_refuses_while_weixin_is_running(self) -> None:
        app.running_weixin_processes = lambda: ["Weixin.exe (PID 123)"]
        with self.assertRaises(app.AppError):
            app.open_direct_source(str(self.source), KEY_HEX)

    def test_extract_database_key_is_verified_read_only_and_not_persisted(self) -> None:
        before_hash = hashlib.sha256(self.message_db.read_bytes()).hexdigest()
        before_names = sorted(str(path.relative_to(self.source)) for path in self.source.rglob("*"))
        original_scanner = app.key_extract.scan_config_cipher_candidates

        def fake_scanner():
            candidates = []
            for salt, raw_key in self.raw_keyring().items():
                candidate = app.key_extract.ConfigCipherCandidate(
                    raw_key.hex(), salt, 4321, "Weixin.exe"
                )
                candidates.append(candidate)
            return app.key_extract.ConfigCipherScanResult(
                candidates=candidates,
                process_count=1,
                opened_process_count=1,
                denied_process_count=0,
                scanned_region_count=3,
                scanned_bytes=4096,
                config_name_hit_count=1,
                config_reference_count=3,
                decoded_blob_count=3,
                elapsed_seconds=0.25,
            )

        app.key_extract.scan_config_cipher_candidates = fake_scanner
        try:
            result = app.extract_database_key(str(self.source))
        finally:
            app.key_extract.scan_config_cipher_candidates = original_scanner

        self.assertEqual(result["process"], "Weixin.exe (PID 4321)")
        self.assertTrue(result["read_only"])
        self.assertFalse(result["persisted"])
        self.assertTrue(result["stored_in_memory"])
        self.assertEqual(result["key_mode"], "sqlcipher-raw-keyring")
        self.assertEqual(result["validated_database_count"], 3)
        self.assertEqual(result["required_database_count"], 3)
        self.assertEqual(result["key_count"], 3)
        self.assertTrue(app.STATE.unlocked)
        self.assertTrue(app.STATE.extracted_keys_match(self.source))
        self.assertEqual(hashlib.sha256(self.message_db.read_bytes()).hexdigest(), before_hash)
        self.assertEqual(
            sorted(str(path.relative_to(self.source)) for path in self.source.rglob("*")),
            before_names,
        )

        opened = app.open_direct_source(str(self.source), "", True)
        self.assertEqual(opened["key_mode"], "sqlcipher-raw-keyring")
        self.assertEqual(len(app.list_conversations()), 1)

    def test_raw_keyring_can_update_message_and_attached_session_database(self) -> None:
        raw_keys = self.raw_keyring()
        app.STATE.set_raw_keys(self.source, raw_keys)
        opened = app.open_direct_source(str(self.source), "", True)
        self.assertEqual(opened["key_mode"], "sqlcipher-raw-keyring")
        conversation = app.list_conversations()[0]
        latest = app.list_messages(conversation["db_rel"], TABLE, 1, 20)["items"][0]
        result = app.update_message(
            latest["db_rel"],
            latest["table"],
            latest["local_id"],
            {"display_content": "raw keyring 更新"},
        )
        self.assertTrue(result["display_sync"]["session_preview_updated"])
        with connect(self.message_db) as connection:
            value = connection.execute(
                f'SELECT message_content FROM "{TABLE}" WHERE local_id=2'
            ).fetchone()[0]
            self.assertEqual(
                zstd.ZstdDecompressor().decompress(bytes(value)).decode("utf-8"),
                f"{SENDER}:\nraw keyring 更新",
            )
        with connect(self.session_db) as connection:
            summary = connection.execute(
                "SELECT summary FROM SessionTable WHERE username=?", (GROUP,)
            ).fetchone()[0]
            self.assertEqual(summary, "raw keyring 更新")

    def test_key_bundle_is_explicit_portable_and_validated_against_selected_directory(self) -> None:
        app.STATE.set_raw_keys(self.source, self.raw_keyring())
        exported = app.export_key_bundle()
        bundle = exported["bundle"]
        self.assertTrue(bundle.startswith(app.KEY_BUNDLE_PREFIX))
        self.assertNotIn(str(self.source), bundle)
        self.assertFalse(exported["persisted"])

        app.STATE.clear_session()
        imported = app.import_key_bundle(self.source, bundle)
        self.assertEqual(imported["validated_database_count"], 3)
        self.assertTrue(app.STATE.extracted_keys_match(self.source))

        opened = app.open_direct_source(str(self.source), bundle)
        self.assertEqual(opened["key_mode"], "imported-raw-keyring")
        self.assertEqual(len(app.list_conversations()), 1)

    def test_tampered_key_bundle_is_rejected(self) -> None:
        app.STATE.set_raw_keys(self.source, self.raw_keyring())
        bundle = app.export_key_bundle()["bundle"]
        encoded = bundle[len(app.KEY_BUNDLE_PREFIX):]
        payload = json.loads(base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4)))
        first_salt = next(iter(payload["keys"]))
        payload["keys"][first_salt] = "00" * 32
        tampered = app.KEY_BUNDLE_PREFIX + base64.urlsafe_b64encode(
            json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ).decode("ascii").rstrip("=")
        app.STATE.clear_session()
        with self.assertRaises(app.AppError):
            app.import_key_bundle(self.source, tampered)
        self.assertFalse(app.STATE.unlocked)

    def test_session_clear_removes_path_keys_jobs_and_capture_state(self) -> None:
        app.STATE.set_raw_keys(self.source, self.raw_keyring())
        app.STATE.source_root = self.source
        app.STATE.mode = "direct"
        app.STATE.jobs["job"] = {"status": "running"}
        app.STATE.capture = {"capture_id": "test", "status": "scanning"}
        app.STATE.clear_session()
        self.assertIsNone(app.STATE.source_root)
        self.assertIsNone(app.STATE.extracted_source_root)
        self.assertFalse(app.STATE.unlocked)
        self.assertEqual(app.STATE.jobs, {})
        self.assertEqual(app.STATE.capture, {"status": "idle"})
        self.assertNotIn("default_source", app.direct_status())

    def test_fast_raw_key_verifier_matches_sqlcipher_database_page(self) -> None:
        salt = app.encrypted_database_salt(self.message_db)
        assert salt is not None
        page = self.message_db.read_bytes()[:app.key_extract.SQLCIPHER_PAGE_SIZE]
        raw_key = self.raw_keyring()[salt]
        self.assertTrue(app.key_extract.verify_sqlcipher4_raw_key(page, raw_key))
        self.assertFalse(app.key_extract.verify_sqlcipher4_raw_key(page, b"\x00" * 32))

    def test_async_capture_waiter_completes_and_commits_only_after_validation(self) -> None:
        original_list = app.key_extract.list_same_session_wechat_processes
        original_scan = app.key_extract.scan_config_cipher_candidates
        app.key_extract.list_same_session_wechat_processes = lambda: [
            app.key_extract.WeChatProcess(pid=9876, name="Weixin.exe")
        ]

        def fake_scan():
            return app.key_extract.ConfigCipherScanResult(
                candidates=[
                    app.key_extract.ConfigCipherCandidate(
                        key.hex(), salt, 9876, "Weixin.exe"
                    )
                    for salt, key in self.raw_keyring().items()
                ],
                process_count=1,
                opened_process_count=1,
                denied_process_count=0,
                scanned_region_count=2,
                scanned_bytes=8192,
                config_name_hit_count=1,
                config_reference_count=3,
                decoded_blob_count=3,
                elapsed_seconds=0.01,
            )

        app.key_extract.scan_config_cipher_candidates = fake_scan
        try:
            started = app.start_key_capture(str(self.source), 30)
            self.assertEqual(started["status"], "waiting_for_weixin")
            assert app.STATE.capture_thread is not None
            app.STATE.capture_thread.join(timeout=5)
            status = app.key_capture_status()
        finally:
            app.key_extract.list_same_session_wechat_processes = original_list
            app.key_extract.scan_config_cipher_candidates = original_scan
        self.assertEqual(status["status"], "complete")
        self.assertEqual(status["result"]["validated_database_count"], 3)
        self.assertTrue(app.STATE.extracted_keys_match(self.source))

    def test_startup_ui_requires_prelogin_order_and_contains_no_prefilled_path(self) -> None:
        html = (Path(app.__file__).parent / "static" / "direct.html").read_text(
            encoding="utf-8"
        )
        self.assertIn("完全退出当前已登录的微信", html)
        self.assertIn("重新打开微信，但暂时不要登录", html)
        self.assertIn("开始等待登录并提取", html)
        self.assertIn('id="insertDirection"', html)
        self.assertIn("对方发送（左侧气泡）", html)
        self.assertIn('id="repairInsertRoutes"', html)
        self.assertIn('id="sourcePath" type="text" value=""', html)
        self.assertNotRegex(html, r'id="sourcePath"[^>]*value="[A-Za-z]:\\')

    def test_key_literal_parser_requires_exact_key_and_matching_salt(self) -> None:
        key = ("a1" * 32).upper()
        salt = ("b2" * 16).upper()
        literal = f"x'{key}{salt}'".encode("ascii")
        payload = b"prefix" + literal + b"suffix x'not-hex'"
        self.assertEqual(
            app.key_extract.find_key_literals(payload, {salt.lower()}),
            [(key.lower(), salt.lower())],
        )
        self.assertEqual(app.key_extract.find_key_literals(payload, {"cc" * 16}), [])

    def test_insert_local_text_uses_sent_identity_and_updates_session_only_when_latest(self) -> None:
        app.open_direct_source(str(self.source), KEY_HEX)
        conversation = app.list_conversations()[0]
        inserted = app.insert_text_message(
            conversation["db_rel"], TABLE, "新增的本地文本", 1700000010
        )
        self.assertTrue(inserted["inserted"])
        self.assertTrue(inserted["local_only"])
        self.assertEqual(inserted["sender_mode"], "self")
        self.assertTrue(inserted["message"]["is_local_inserted"])
        self.assertEqual(inserted["message"]["local_insert_direction"], "self")
        self.assertEqual(inserted["message"]["display_content"], "新增的本地文本")
        self.assertTrue(inserted["display_sync"]["session_preview_updated"])
        new_local_id = inserted["message"]["local_id"]

        with connect(self.message_db) as connection:
            self_id = connection.execute(
                "SELECT rowid FROM Name2Id WHERE user_name=?", (SELF,)
            ).fetchone()[0]
            row = connection.execute(
                f'SELECT * FROM "{TABLE}" WHERE local_id=?', (new_local_id,)
            ).fetchone()
            self.assertEqual(row["real_sender_id"], self_id)
            self.assertEqual(row["status"], 2)
            self.assertEqual(row["upload_status"], 0)
            self.assertEqual(row["server_seq"], 0)
            self.assertEqual(row["origin_source"], 6)
            self.assertEqual(
                bytes(row["packed_info_data"]),
                app.build_text_packed_route(self_id, 1),
            )
            self.assertNotEqual(row["server_id"], 0)
            self.assertEqual(
                row["server_id"] & 0xFF00000000000000, app.LOCAL_SERVER_ID_PREFIX
            )
            self.assertEqual(row["sort_seq"], 1700000010000)
            self.assertEqual(row["message_content"], "新增的本地文本")
            self.assertIn(app.LOCAL_INSERT_SOURCE_MARKER, row["source"])
            self.assertIn("<direction>self</direction>", row["source"])
            self.assertIsNone(row["WCDB_CT_message_content"])
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

        with connect(self.session_db) as connection:
            session = connection.execute(
                "SELECT * FROM SessionTable WHERE username=?", (GROUP,)
            ).fetchone()
            self.assertEqual(session["summary"], "新增的本地文本")
            self.assertEqual(session["last_msg_locald_id"], new_local_id)
            self.assertEqual(session["last_timestamp"], 1700000010)
            self.assertEqual(session["sort_timestamp"], 1700000010)
            self.assertEqual(session["last_msg_type"], 1)
            self.assertEqual(session["last_msg_sender"], SELF)
            self.assertEqual(session["last_sender_display_name"], "")

        historical = app.insert_text_message(
            conversation["db_rel"], TABLE, "插入到历史位置", 1600000000
        )
        self.assertFalse(historical["display_sync"]["session_preview_updated"])
        self.assertEqual(historical["display_sync"]["reason"], "historical_insert")
        with connect(self.session_db) as connection:
            session = connection.execute(
                "SELECT summary,last_msg_locald_id FROM SessionTable WHERE username=?", (GROUP,)
            ).fetchone()
            self.assertEqual(session["summary"], "新增的本地文本")
            self.assertEqual(session["last_msg_locald_id"], new_local_id)

        reopened = app.list_messages(conversation["db_rel"], TABLE, 1, 20)
        self.assertEqual(reopened["items"][0]["display_content"], "新增的本地文本")
        self.assertTrue(reopened["items"][0]["is_local_inserted"])
        self.assertFalse((self.source / "editor_audit.db").exists())
        self.assertFalse(any(self.root.glob("*snapshot*")))

    def test_insert_group_message_from_other_uses_left_side_route_and_sender_prefix(self) -> None:
        with connect(self.message_db) as connection:
            connection.execute(
                "INSERT INTO Name2Id(user_name,is_session) VALUES(?,0)",
                ("wxid_nontext_only",),
            )
            nontext_id = int(connection.execute("SELECT last_insert_rowid()").fetchone()[0])
            connection.execute(
                f'INSERT INTO "{TABLE}"(server_id,local_type,sort_seq,real_sender_id,'
                "create_time,status,upload_status,download_status,server_seq,origin_source,"
                "source,message_content) VALUES(12,3,1699999999000,?,1699999999,4,0,0,0,6,?,?)",
                (nontext_id, "<msgsource />", "[图片]"),
            )
            connection.commit()
        app.open_direct_source(str(self.source), KEY_HEX)
        options = app.insert_message_options(
            "db_storage/message/message_0.db", TABLE
        )
        self.assertTrue(options["is_group"])
        self.assertNotIn(
            "wxid_nontext_only",
            {item["username"] for item in options["other_senders"]},
        )
        self_id = int(options["self_sender"]["id"])
        sender = next(
            item for item in options["other_senders"] if item["username"] == SENDER
        )
        with self.assertRaises(app.AppError):
            app.insert_text_message(
                "db_storage/message/message_0.db",
                TABLE,
                "不应写入",
                1700000010,
                "other",
                999999,
            )

        inserted = app.insert_text_message(
            "db_storage/message/message_0.db",
            TABLE,
            "模拟对方发送",
            1700000015,
            "other",
            sender["id"],
        )
        self.assertEqual(inserted["sender_mode"], "other")
        self.assertEqual(inserted["sender"]["username"], SENDER)
        self.assertEqual(inserted["message"]["display_content"], "模拟对方发送")
        self.assertTrue(inserted["message"]["content_has_group_prefix"])
        self.assertEqual(inserted["message"]["local_insert_direction"], "other")
        local_id = inserted["message"]["local_id"]

        with connect(self.message_db) as connection:
            row = connection.execute(
                f'SELECT * FROM "{TABLE}" WHERE local_id=?', (local_id,)
            ).fetchone()
            self.assertEqual(row["real_sender_id"], sender["id"])
            self.assertEqual(row["status"], 4)
            self.assertEqual(row["origin_source"], 6)
            self.assertEqual(row["server_seq"], 0)
            self.assertEqual(row["message_content"], f"{SENDER}:\n模拟对方发送")
            self.assertEqual(
                bytes(row["packed_info_data"]),
                app.build_text_packed_route(1, self_id),
            )
            self.assertIn("<direction>other</direction>", row["source"])

        with connect(self.session_db) as connection:
            session = connection.execute(
                "SELECT summary,last_msg_sender,last_sender_display_name "
                "FROM SessionTable WHERE username=?",
                (GROUP,),
            ).fetchone()
            self.assertEqual(session["summary"], "模拟对方发送")
            self.assertEqual(session["last_msg_sender"], SENDER)
            self.assertEqual(session["last_sender_display_name"], "")

    def test_insert_private_message_from_other_uses_contact_to_self_route(self) -> None:
        peer_id, self_id = add_private_conversation(self.message_db, self.session_db)
        app.open_direct_source(str(self.source), KEY_HEX)
        db_rel = "db_storage/message/message_0.db"
        options = app.insert_message_options(db_rel, PRIVATE_TABLE)
        self.assertFalse(options["is_group"])
        self.assertEqual(options["other_senders"][0]["id"], peer_id)

        inserted = app.insert_text_message(
            db_rel,
            PRIVATE_TABLE,
            "私聊对方发送",
            1700000020,
            "other",
        )
        self.assertEqual(inserted["sender_mode"], "other")
        self.assertEqual(inserted["message"]["display_content"], "私聊对方发送")
        self.assertFalse(inserted["message"]["content_has_group_prefix"])
        local_id = inserted["message"]["local_id"]
        with connect(self.message_db) as connection:
            row = connection.execute(
                f'SELECT * FROM "{PRIVATE_TABLE}" WHERE local_id=?', (local_id,)
            ).fetchone()
            self.assertEqual(row["real_sender_id"], peer_id)
            self.assertEqual(row["status"], 4)
            self.assertEqual(row["message_content"], "私聊对方发送")
            self.assertEqual(
                bytes(row["packed_info_data"]),
                app.build_text_packed_route(peer_id, self_id),
            )
        with connect(self.session_db) as connection:
            session = connection.execute(
                "SELECT summary,last_msg_sender FROM SessionTable WHERE username=?",
                (PEER,),
            ).fetchone()
            self.assertEqual(session["summary"], "私聊对方发送")
            self.assertEqual(session["last_msg_sender"], PEER)

    def test_repair_legacy_local_insert_adds_missing_right_side_route_only_once(self) -> None:
        legacy_source = (
            f"<msgsource><localonly>{app.LOCAL_INSERT_SOURCE_MARKER}"
            "</localonly></msgsource>"
        )
        with connect(self.message_db) as connection:
            self_id = int(
                connection.execute(
                    "SELECT rowid FROM Name2Id WHERE user_name=?", (SELF,)
                ).fetchone()[0]
            )
            cursor = connection.execute(
                f'INSERT INTO "{TABLE}"('
                "server_id,local_type,sort_seq,real_sender_id,create_time,status,"
                "upload_status,download_status,server_seq,origin_source,source,"
                "message_content,packed_info_data) VALUES(99,1,1700000002000,?,"
                "1700000002,2,0,0,0,6,?,?,NULL)",
                (self_id, legacy_source, "旧版新增的本人消息"),
            )
            legacy_local_id = int(cursor.lastrowid)
            untouched_before = bytes(
                connection.execute(
                    f'SELECT message_content FROM "{TABLE}" WHERE local_id=2'
                ).fetchone()[0]
            )
            connection.commit()

        app.open_direct_source(str(self.source), KEY_HEX)
        repaired = app.repair_local_insert_routes()
        self.assertEqual(repaired["row_count"], 1)
        self.assertEqual(repaired["table_count"], 1)
        self.assertEqual(repaired["database_count"], 1)

        with connect(self.message_db) as connection:
            row = connection.execute(
                f'SELECT * FROM "{TABLE}" WHERE local_id=?', (legacy_local_id,)
            ).fetchone()
            self.assertEqual(row["real_sender_id"], self_id)
            self.assertEqual(row["status"], 2)
            self.assertEqual(row["origin_source"], 6)
            self.assertEqual(
                bytes(row["packed_info_data"]),
                app.build_text_packed_route(self_id, 1),
            )
            self.assertIn("<direction>self</direction>", row["source"])
            untouched_after = bytes(
                connection.execute(
                    f'SELECT message_content FROM "{TABLE}" WHERE local_id=2'
                ).fetchone()[0]
            )
            self.assertEqual(untouched_after, untouched_before)
            self.assertEqual(connection.execute("PRAGMA quick_check").fetchone()[0], "ok")

        repaired_again = app.repair_local_insert_routes()
        self.assertEqual(repaired_again["row_count"], 0)
        self.assertEqual(repaired_again["database_count"], 0)


if __name__ == "__main__":
    unittest.main()
