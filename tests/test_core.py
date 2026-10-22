from __future__ import annotations

import hashlib
import tempfile
import unittest
from pathlib import Path

import zstandard as zstd
from sqlcipher3 import dbapi2 as sqlcipher

import app


KEY_HEX = "11" * 32
USERNAME = "wxid_test_contact"
TABLE = "Msg_" + hashlib.md5(USERNAME.encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    digest.update(path.read_bytes())
    return digest.hexdigest()


def create_message_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlcipher.connect(str(path))
    connection.set_key(bytes.fromhex(KEY_HEX))
    connection.execute("CREATE TABLE Name2Id(user_name TEXT PRIMARY KEY, is_session INTEGER)")
    connection.execute("INSERT INTO Name2Id(user_name,is_session) VALUES(?,1)", (USERNAME,))
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
        "WCDB_CT_message_content,WCDB_CT_source) VALUES(1,1,1,1,1700000000,2,0,0,1,0,?,?,0,0)",
        ("<msgsource />", "原始文本"),
    )
    compressed = zstd.ZstdCompressor(level=3).compress("压缩文本".encode("utf-8"))
    connection.execute(
        f'INSERT INTO "{TABLE}"(server_id,local_type,sort_seq,real_sender_id,create_time,status,'
        "upload_status,download_status,server_seq,origin_source,source,message_content,"
        "WCDB_CT_message_content,WCDB_CT_source) VALUES(2,1,2,1,1700000001,2,0,0,2,0,?,?,4,0)",
        ("", compressed),
    )
    connection.commit()
    connection.close()


def create_contact_database(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlcipher.connect(str(path))
    connection.set_key(bytes.fromhex(KEY_HEX))
    connection.execute("CREATE TABLE contact(username TEXT, remark TEXT, nick_name TEXT)")
    connection.execute(
        "INSERT INTO contact(username,remark,nick_name) VALUES(?,?,?)",
        (USERNAME, "测试备注", "测试昵称"),
    )
    connection.commit()
    connection.close()


class CoreWorkflowTest(unittest.TestCase):
    def setUp(self) -> None:
        app.STATE.clear_key()
        app.STATE.snapshot_root = None
        app.STATE.source_root = None
        app.STATE.manifest = None
        app.STATE.mode = None
        app.STATE.jobs.clear()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.source = self.root / "account"
        self.target = self.root / "snapshot"
        self.message_db = self.source / "db_storage" / "message" / "message_0.db"
        self.contact_db = self.source / "db_storage" / "contact" / "contact.db"
        create_message_database(self.message_db)
        create_contact_database(self.contact_db)
        self.original_hashes = {
            self.message_db: sha256(self.message_db),
            self.contact_db: sha256(self.contact_db),
        }
        self.original_process_probe = app.running_weixin_processes
        app.running_weixin_processes = lambda: []

    def tearDown(self) -> None:
        app.running_weixin_processes = self.original_process_probe
        app.STATE.clear_key()
        app.STATE.mode = None
        self.temporary.cleanup()

    def test_copy_edit_delete_undo_never_changes_source(self) -> None:
        job_id = "unit-test"
        app.STATE.jobs[job_id] = {"id": job_id, "status": "running"}
        app.snapshot_worker(job_id, str(self.source), str(self.target))
        self.assertEqual(app.STATE.jobs[job_id]["status"], "completed")
        self.assertTrue((self.target / "snapshot_manifest.json").is_file())
        self.assertNotIn(KEY_HEX, (self.target / "snapshot_manifest.json").read_text("utf-8"))
        for path, digest in self.original_hashes.items():
            self.assertEqual(sha256(path), digest)

        app.unlock_snapshot(KEY_HEX)
        conversations = app.list_conversations()
        self.assertEqual(len(conversations), 1)
        self.assertEqual(conversations[0]["display_name"], "测试备注")
        listing = app.list_messages(conversations[0]["db_rel"], TABLE, 1, 20)
        self.assertEqual(listing["total"], 2)
        self.assertEqual(listing["items"][0]["message_content"], "压缩文本")

        item = listing["items"][0]
        app.update_message(
            item["db_rel"], item["table"], item["local_id"], {"message_content": "修改后的压缩文本"}
        )
        updated = app.list_messages(item["db_rel"], item["table"], 1, 20)
        self.assertEqual(updated["items"][0]["message_content"], "修改后的压缩文本")
        self.assertEqual(updated["items"][0]["content_storage"], "zstd")

        delete_id = updated["items"][1]["local_id"]
        deletion = app.delete_message(item["db_rel"], item["table"], delete_id)
        self.assertEqual(app.list_messages(item["db_rel"], item["table"], 1, 20)["total"], 1)
        app.undo_audit(deletion["audit_id"])
        self.assertEqual(app.list_messages(item["db_rel"], item["table"], 1, 20)["total"], 2)

        for path, digest in self.original_hashes.items():
            self.assertEqual(sha256(path), digest)
        self.assertTrue(app.verify_snapshot()["ok"])
        self.assertTrue(app.quick_check_databases()["ok"])

    def test_rejects_overlapping_target(self) -> None:
        with self.assertRaises(app.AppError):
            app.ensure_separate_paths(self.source, self.source / "nested")


if __name__ == "__main__":
    unittest.main()
