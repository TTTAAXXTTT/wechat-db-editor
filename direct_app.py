from __future__ import annotations

import os
import sys

import app


app.APP_NAME = "微信数据库直接编辑器"
app.APP_VERSION = "2.0.0"
app.DEFAULT_PAGE = "direct.html"


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(app.packaged_self_test())
    if "--key-extraction-self-test" in sys.argv:
        source = os.environ.get("WECHAT_EDITOR_TEST_SOURCE", "").strip()
        if not source:
            raise SystemExit(22)
        try:
            result = app.extract_database_key(source)
            ok = bool(
                result.get("read_only")
                and result.get("stored_in_memory")
                and not result.get("persisted")
                and int(result.get("key_count") or 0) > 0
                and result.get("validated_database_count")
                == result.get("required_database_count")
            )
        except Exception:
            ok = False
        finally:
            app.STATE.clear_session()
        raise SystemExit(0 if ok else 21)
    raise SystemExit(app.main(open_browser="--no-browser" not in sys.argv))
