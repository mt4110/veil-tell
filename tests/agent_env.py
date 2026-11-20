"""Exercise the generated shell environment with local curl and npm TLS clients."""
import base64
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def trial(fixture, node_root, cache=False):
    with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
        root = Path(tmp).resolve()
        project = root / "project"
        project.mkdir()
        home = root / "home"
        home.mkdir()
        ca = project / "registry.crt"
        key = root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=allowed.test", "-addext", "subjectAltName=DNS:allowed.test",
                        "-keyout", key, "-out", ca], check=True, capture_output=True)
        pkg = {"name": "sample", "version": "1.0.0"}
        data = json.dumps(pkg).encode()
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            entry = tarfile.TarInfo("package/package.json")
            entry.size = len(data)
            archive.addfile(entry, io.BytesIO(data))
        tarball = stream.getvalue()
        pkg["dist"] = {"tarball": "https://allowed.test/sample.tgz", "integrity": "sha512-" +
                       base64.b64encode(hashlib.sha512(tarball).digest()).decode()}
        metadata = json.dumps({"name":"sample", "versions":{"1.0.0":pkg},"dist-tags":{"latest":"1.0.0"}}).encode()
        requests = []

        class Registry(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                body = tarball if self.path == "/sample.tgz" else metadata
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *_):
                pass

        with ThreadingHTTPServer(("127.0.0.1", 0), Registry) as server:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(ca, key)
            server.socket = tls.wrap_socket(server.socket, server_side=True)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            runtime = Path(node_root).resolve()
            if sys.platform == "linux":
                shutil.copytree(runtime, project / "runtime", symlinks=True)
                runtime = project / "runtime"
            env = dict(os.environ, HOME=str(home), XDG_STATE_HOME=str(root / "state"),
                       VEIL_TELL_FIXTURE_RECEIVER=f"127.0.0.1:{server.server_port}",
                       NO_PROXY="*", PATH=f"{runtime / 'bin'}:{os.environ['PATH']}")
            env.pop("CI", None)
            env.pop("VEIL_TELL_LOG", None)
            def run(cmd, *, code=0, extra=None):
                p = subprocess.run(cmd, cwd=project, env=dict(env, **(extra or {})),
                                   capture_output=True, text=True, timeout=35)
                assert code is None or p.returncode == code, (cmd, p.stdout, p.stderr)
                return p
            setup = run([fixture, "agent-env"]).stdout
            def shell(args, **kw):
                return run(["/bin/sh","-c",setup+'\nexec "$@"', "test", *args],**kw)
            npm = ["npm","install","sample@1.0.0","--registry=https://allowed.test",
                   "--cafile="+str(ca),"--no-audit","--no-fund","--fetch-retries=0"]
            if cache:
                opts = {"VEIL_TELL_CACHE":"persistent"}
                times = []
                for attempt in range(2):
                    fresh = project / str(attempt)
                    fresh.mkdir()
                    (fresh / "package.json").write_text('{"name":"cache-trial","version":"1.0.0"}')
                    started = time.monotonic()
                    shell([*npm,"--prefix",str(fresh)]+(["--offline"] if attempt else []),extra=opts)
                    times.append(time.monotonic()-started)
                    assert (fresh/"node_modules/sample/package.json").is_file()
                assert not (home/".npm").exists()
                assert (home/".cache/veil-tell/npm/_cacache").is_dir()
                print(f"persistent npm cold={times[0]:.3f}s offline={times[1]:.3f}s")
                server.shutdown()
                return
            (project/"package.json").write_text('{"name":"session-test","version":"1.0.0"}')
            shell(npm)
            secret = "Q" * 45
            curl = ["curl","-fsS","--cacert",str(ca),"-H","Authorization: Bearer shortsecret",
                    "https://allowed.test/private?token=othersecret"]
            shell(curl)
            logs = list((root/"state/veil-tell/log").glob("*.jsonl"))
            path, = logs
            entries = [json.loads(line) for line in path.read_text().splitlines()]
            assert [r["argv"][0] for r in entries] == ["npm","curl"]
            assert all(r["destinations"][0]["host"]=="allowed.test" for r in entries)
            assert not (project/".veil-tell/npm.json").exists()
            shell(curl, extra={"VEIL_TELL_LOG":"off"})
            assert len(path.read_text().splitlines())==2
            run([fixture,"--log","true","--password","briefsecret",secret])
            assert all(s not in path.read_text() for s in ("private?", "othersecret","shortsecret","briefsecret",secret))
            blocked=shell(["curl","-fsS","https://fixture.local"],code=None)
            assert blocked.returncode != 0
            last=json.loads(path.read_text().splitlines()[-1])
            golden=f'{last["clock"]}  curl -fsS https://fixture.local  exit {blocked.returncode}\n          ✗ fixture.local:443  ×1  0 B  non_public_destination\n'
            assert run([fixture,"log","--today","--only-blocked"]).stdout == golden
            expired = path.with_name("2000-01-01.jsonl")
            unrelated = path.with_name("notes.txt")
            expired.write_text("{}\n")
            unrelated.write_text("keep")
            run([fixture,"--log","observe","--report",str(ca),"--","true"],code=125)
            assert not expired.exists() and unrelated.read_text() == "keep"
            failed = json.loads(path.read_text().splitlines()[-1])
            assert failed["run_status"]["reason"] == "setup_failed" and failed["coverage"] is None
            server.shutdown()
    print("PASS: shell shims, TLS receiver, private local log and blocked timeline")

if __name__ == "__main__":
    trial(str(Path(sys.argv[1]).resolve()),sys.argv[2])
