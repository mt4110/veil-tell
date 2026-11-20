"""Exercise the generated shell environment with local curl and npm TLS clients."""
import base64
import hashlib
import io
import json
import os
import pty
import select
import signal
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
                        "-subj", "/CN=allowed.test", "-addext", "subjectAltName=DNS:allowed.test,DNS:new.test,IP:127.0.0.1",
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
            def run(cmd, *, code=0, extra=None, input=None):
                p = subprocess.run(cmd, cwd=project, env=dict(env, **(extra or {})),
                                   input=input, capture_output=True, text=True, timeout=35)
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
            # curl obtains its only URL from stdin. Exercise both shim entry points,
            # then check that opting into logging on the ordinary CLI still gets EOF.
            config = 'url = "https://allowed.test/from-stdin"\n'
            from_stdin = ["curl", "-fsS", "--cacert", str(ca), "--config", "-"]
            start = requests.count("/from-stdin")
            shell(from_stdin, input=config)
            run([fixture, "agent", "--", *from_stdin], input=config)
            assert requests.count("/from-stdin") == start + 2
            direct = run([fixture, "--log", "--", *from_stdin], input=config, code=None)
            assert direct.returncode != 0 and requests.count("/from-stdin") == start + 2
            # Both commands share the shell's redirected file description.
            # curl --version should leave even a nonzero starting offset untouched.
            source = root / "input.txt"
            source.write_bytes(b"prefix:remaining input\n")
            with source.open("rb") as stream:
                stream.seek(len(b"prefix:"))
                result = subprocess.run(["/bin/sh", "-c", setup + "\ncurl --version >/dev/null && cat"],
                                        cwd=project, env=env, stdin=stream, capture_output=True, timeout=10)
                assert result.returncode == 0 and result.stdout == b"remaining input\n", (result.stdout, result.stderr)
            # A terminal supplies bytes and EOF to the supervised process as well.
            master, slave = pty.openpty()
            try:
                os.write(master, config.encode() + b"\x04")
                with subprocess.Popen(["/bin/sh", "-c", setup + '\nexec "$@"', "test", *from_stdin],
                                      cwd=project, env=env, stdin=slave,
                                      stdout=subprocess.PIPE, stderr=subprocess.PIPE) as child:
                    stdout, stderr = child.communicate(timeout=10)
                    assert child.returncode == 0, (stdout, stderr)
            finally:
                os.close(slave)
                os.close(master)
            assert requests.count("/from-stdin") == start + 3
            assert "/from-stdin" not in path.read_text()
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
            project_agent = project / "agent-install"
            project_agent.mkdir()
            (project_agent / "package.json").write_text('{"name":"agent-install","version":"1.0.0"}')
            agent = project / "fixture-agent.cjs"
            agent.write_text("""
const {readFileSync} = require('node:fs');
const {execFileSync} = require('node:child_process');
(async () => {
  if (readFileSync(0, 'utf8') !== 'interactive input' || process.argv[2] !== 'private prompt') process.exit(2);
  for (const url of [process.env.LOCAL_URL, 'https://new.test/api?key=private-query']) {
    const response = await fetch(url, {headers: {Authorization: 'Bearer private-api-key'}});
    if (!response.ok) process.exit(3);
    await response.text();
  }
  execFileSync('npm', process.argv.slice(3), {stdio:'inherit'});
  console.log('agent output');
})().catch(e => {console.error(e);process.exit(4)});
""")
            # This local CONNECT proxy terminates the fixture TLS connection itself.
            # Both collectors must use it exactly once per CONNECT, with the original credentials.
            tunnels = []
            class Upstream(BaseHTTPRequestHandler):
                def do_CONNECT(self):
                    if self.path not in ("new.test:443", "allowed.test:443") or self.headers.get("Proxy-Authorization") != "Basic " + base64.b64encode(b"fixture:private-upstream").decode():
                        self.send_error(403)
                        return
                    tunnels.append(self.path)
                    self.send_response(200)
                    self.end_headers()
                    with tls.wrap_socket(self.connection, server_side=True) as connection:
                        Registry(connection, self.client_address, self.server)

                def log_message(self, *_):
                    pass

            with ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as upstream:
                threading.Thread(target=upstream.serve_forever, daemon=True).start()
                endpoint = f"http://fixture:private-upstream@127.0.0.1:{upstream.server_port}"
                bypass = "127.0.0.1,private-exclusion.test"
                local_url = f"https://127.0.0.1:{server.server_port}/bypassed"
                agent_env = dict(env, HTTPS_PROXY=endpoint, https_proxy=endpoint,
                                 NO_PROXY=bypass, no_proxy=bypass, NODE_EXTRA_CA_CERTS=str(ca), LOCAL_URL=local_url)
                before = len(path.read_text().splitlines())
                result = subprocess.run([fixture, "agent", "--", "node", agent, "private prompt",
                                         *npm[1:], "--prefix", project_agent], cwd=project, env=agent_env,
                                        input="interactive input", capture_output=True, text=True, timeout=35)
                assert result.returncode == 0 and "agent output" in result.stdout, (result.stdout, result.stderr)
                assert (project_agent / "node_modules/sample/package.json").is_file()
                child, parent = [json.loads(line) for line in path.read_text().splitlines()[before:]]
                assert child["argv"][0] == "npm" and parent["argv"] == ["node"] and parent["scope"] == "agent_session"
                for row, host in [(child, "allowed.test"), (parent, "new.test")]:
                    dest, = row["destinations"]
                    assert (dest["host"], dest["decision"], dest["reason"]) == (host, "allow", "observe"), row
                    assert dest["sent_bytes"] > 0 and dest["attempts"] == tunnels.count(host + ":443")
                assert "/bypassed" in requests and "/api?key=private-query" in requests
                assert parent["coverage"]["direct_attempt_destinations"] == "not_observed"
                assert all(secret not in path.read_text() for secret in
                           ("private prompt", "private-query", "private-api-key", "private-upstream", "private-exclusion"))
                upstream.shutdown()

            master, slave = pty.openpty()
            try:
                result = subprocess.run([fixture, "agent", "--", "/bin/sh", "-c",
                                         "test -t 0 && test -t 1 && test -t 2 && exit 17"],
                                        cwd=project, env=env, stdin=slave, stdout=slave, stderr=slave, timeout=8)
                assert result.returncode == 17, result.returncode
            finally:
                os.close(slave)
                os.close(master)
            with subprocess.Popen([fixture, "agent", "--", "/bin/sh", "-c",
                                   "trap 'exit 42' TERM; echo ready; while :; do sleep 0.1; done"],
                                  cwd=project, env=env, stdout=subprocess.PIPE, text=True) as child:
                assert select.select([child.stdout], [], [], 8)[0], "agent did not start"
                assert child.stdout.readline() == "ready\n"
                child.send_signal(signal.SIGTERM)
                assert child.wait(timeout=8) == 42
            before = path.read_bytes()
            run([fixture, "agent", "--", "true"], extra={"VEIL_TELL_LOG":"off"})
            assert path.read_bytes() == before
            server.shutdown()
    print("PASS: shell shims, TLS receiver, private local log, blocked timeline and interactive agent/child TLS observation")

if __name__ == "__main__":
    trial(str(Path(sys.argv[1]).resolve()),sys.argv[2])
