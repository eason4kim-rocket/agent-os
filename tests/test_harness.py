"""AgentOS harness 回归测试（unittest，stdlib only）。

运行：python3 -m unittest discover tests -v
覆盖审计报告（docs/AUDIT-2026-10-26.md）的全部已修复项：
逃逸拒绝、账本篡改/截断/重放/签名、write_file、快照往返、ed25519。
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from harness import ed25519
from harness.ledger import Ledger
from harness.policy import Policy
from harness.sandbox import PlainSandbox
from harness.snapshot import SnapshotManager
from harness.tools import dispatch


def fresh_policy(tmp: Path) -> Policy:
    wd = tmp / "work"
    wd.mkdir(parents=True, exist_ok=True)
    return Policy(workdir=wd)


class EscapeDenialTest(unittest.TestCase):
    """H1 回归：run_command 操作数逃逸必须全部拒绝。"""

    ESCAPES = [
        (["cat", "/etc/passwd"], "读逃逸"),
        (["grep", "-r", "x", "/etc"], "递归读逃逸"),
        (["cp", "/etc/passwd", "stolen.txt"], "外进笼"),
        (["cp", "a.txt", "/tmp/stolen"], "笼外出"),
        (["mv", "a.txt", "/etc/moved"], "mv 到 /etc"),
        (["mkdir", "/tmp/escape"], "mkdir /tmp"),
        (["sh", "-c", "id"], "白名单外命令"),
        (["find", ".", "-delete"], "破坏性选项"),
        (["find", ".", "-exec", "ls"], "破坏性选项 -exec"),
    ]

    def test_all_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fresh_policy(Path(tmp))
            (p.resolved_workdir() / "a.txt").write_text("x")
            for argv, why in self.ESCAPES:
                ok, reason = p.validate_run_command(argv)
                self.assertFalse(ok, f"{why} 未被拒绝: {argv}")

    def test_legit_allowed(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fresh_policy(Path(tmp))
            self.assertTrue(p.validate_run_command(["ls"])[0])
            self.assertTrue(p.validate_run_command(["mkdir", "-p", "2026-01"])[0])

    def test_symlink_escape(self):
        """笼内符号链接指向笼外 → 必须拒绝。"""
        with tempfile.TemporaryDirectory() as tmp:
            p = fresh_policy(Path(tmp))
            outside = Path(tmp) / "outside"
            outside.mkdir()
            (outside / "secret").write_text("s")
            link = p.resolved_workdir() / "leak"
            link.symlink_to(outside)
            self.assertFalse(p.path_allowed_read("leak/secret")[0])


class LedgerTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "ledger.jsonl"
        self.anchor = Path(self.tmp.name) / "ledger.anchor"
        self.led = Ledger(self.path)

    def test_chain_and_verify(self):
        for i in range(5):
            self.led.append("tool.result", "r1", i=i)
        ok, n, bad = self.led.verify()
        self.assertTrue(ok)
        self.assertEqual(n, 5)

    def test_empty_ledger_fails(self):
        ok, _, why = self.led.verify(self.anchor)
        self.assertFalse(ok)
        self.assertIn("空", why)

    def test_tamper_detected(self):
        self.led.append("run.start", "r1")
        self.led.append("tool.result", "r1", rc=0)
        lines = self.path.read_text().splitlines()
        e = json.loads(lines[1])
        e["detail"]["rc"] = 999
        lines[1] = json.dumps(e, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        self.path.write_text("\n".join(lines) + "\n")
        ok, _, why = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("篡改", why)
        self.assertIn("seq", why)  # 必须指明行号

    def test_truncation_detected_by_anchor(self):
        self.led.append("a", "r")
        self.led.append("b", "r")
        self.led.append("c", "r")
        self.led.anchor(self.anchor)
        lines = self.path.read_text().splitlines()
        self.path.write_text("\n".join(lines[:1]) + "\n")
        ok, _, why = Ledger(self.path).verify(self.anchor)
        self.assertFalse(ok)
        self.assertIn("截断", why)

    def test_corrupt_line_no_crash(self):
        self.led.append("a", "r")
        with self.path.open("a") as f:
            f.write('{"schema": "agentos.led\n')  # 半行（模拟断电）
        ok, _, why = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("解析失败", why)

    def test_signature_field_verified(self):
        import hashlib
        from harness import identity as ident
        seed, pk = ident.ensure_identity(Path(self.tmp.name))
        digest = hashlib.sha256(b"policy").hexdigest()
        sig = ident.sign_digest(seed, bytes.fromhex(digest))
        self.led.append("run.start", "r", agent_pubkey=pk.hex(),
                        signed=digest, agent_sig=sig.hex())
        ok, _, _ = self.led.verify()
        self.assertTrue(ok)
        # L5：原地换公钥（保留原签名）→ 链内合法重算后，verify() 必须报"身份签名不匹配"
        import json as _json
        e = self.led.entries[-1]
        e["detail"]["agent_pubkey"] = ("ff" * 32)
        from harness.ledger import GENESIS
        no_hash = {k: v for k, v in e.items() if k != "hash"}
        digest = hashlib.sha256(
            (GENESIS + json.dumps(no_hash, sort_keys=True, ensure_ascii=False,
                                  separators=(",", ":"))).encode()).hexdigest()
        e["hash"] = digest
        self.path.write_text(json.dumps(e, sort_keys=True, ensure_ascii=False,
                                        separators=(",", ":")) + "\n", encoding="utf-8")
        ok, _, why = Ledger(self.path).verify()
        self.assertFalse(ok)
        self.assertIn("身份签名", why)
        # 底层原语：签名对不上
        self.assertFalse(ed25519.checkvalid(
            bytes.fromhex(e["detail"]["agent_sig"]),
            bytes.fromhex(e["detail"]["signed"]),
            bytes.fromhex(e["detail"]["agent_pubkey"])))


import threading


class LedgerConcurrencyTest(unittest.TestCase):
    """L6：并发追加不断链（两个实例交错写）。"""

    def test_concurrent_append_chain_valid(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "ledger.jsonl"
            ledgers = [Ledger(path), Ledger(path)]

            def append_many(led, tag):
                for i in range(10):
                    led.append("tool.result", f"run-{tag}", i=i)

            threads = [threading.Thread(target=append_many, args=(led, t)) for t, led in enumerate(ledgers)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            ok, n, why = Ledger(path).verify()
            self.assertTrue(ok, f"并发追加后断链: {why}")
            self.assertEqual(n, 20)


class WriteFileTest(unittest.TestCase):
    """H2 回归：write_file 必须可用（曾因借用白名单外命令 100% 失败）。"""

    def test_write_file_plain(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fresh_policy(Path(tmp))
            events = []
            res, done = dispatch("write_file", {"path": "out.txt", "content": "你好"},
                                 p, PlainSandbox(), on_event=lambda e, **d: events.append((e, d)))
            self.assertFalse(done)
            self.assertEqual(res, "写入成功")
            self.assertEqual((p.resolved_workdir() / "out.txt").read_text(), "你好")

    def test_write_file_outside_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            p = fresh_policy(Path(tmp))
            res, _ = dispatch("write_file", {"path": "../evil.txt", "content": "x"},
                              p, PlainSandbox(), on_event=lambda e, **d: None)
            self.assertIn("策略拒绝", res)


class SnapshotTest(unittest.TestCase):
    def test_roundtrip(self):
        with tempfile.TemporaryDirectory() as tmp:
            wd = Path(tmp) / "work"
            wd.mkdir()
            (wd / "f.txt").write_text("v1")
            sm = SnapshotManager(wd, Path(tmp) / "state")
            sid = sm.create("r")
            (wd / "f.txt").write_text("v2")
            (wd / "new.txt").write_text("n")
            sm.restore(sid)
            self.assertEqual((wd / "f.txt").read_text(), "v1")
            self.assertFalse((wd / "new.txt").exists())

    def test_sid_traversal_denied(self):
        with tempfile.TemporaryDirectory() as tmp:
            sm = SnapshotManager(Path(tmp) / "work", Path(tmp) / "state")
            with self.assertRaises(ValueError):
                sm.restore("../../etc")

    def test_tampered_manifest_detected(self):
        with tempfile.TemporaryDirectory() as tmp:
            wd = Path(tmp) / "work"
            wd.mkdir()
            (wd / "f.txt").write_text("v1")
            sm = SnapshotManager(wd, Path(tmp) / "state")
            sid = sm.create("r")
            snap = Path(tmp) / "state" / "snapshots" / sid
            (snap / "f.txt").write_text("tampered")  # 篡改快照内容但不动 MANIFEST
            with self.assertRaises(ValueError):
                sm.restore(sid)


class Ed25519Test(unittest.TestCase):
    def test_rfc8032_vector1_pk(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(ed25519.publickey(sk).hex(),
                         "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")

    def test_roundtrip_and_tamper(self):
        sk = bytes(32)  # 全零种子也是合法输入
        pk = ed25519.publickey(sk)
        m = b"hello agent os"
        sig = ed25519.signature(m, sk, pk)
        self.assertTrue(ed25519.checkvalid(sig, m, pk))
        self.assertFalse(ed25519.checkvalid(sig, m + b"x", pk))


if __name__ == "__main__":
    unittest.main()
