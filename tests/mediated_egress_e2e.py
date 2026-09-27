#!/usr/bin/env python3
"""Linux/KVM integration check for the mediated API and branch lifecycle.

Run with SMOLVM_E2E_BIN=/path/to/smolvm python3 tests/mediated_egress_e2e.py.
Uses isolated XDG directories and cleans up its machines and API server.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def read_exact(sock, length):
    data = b""
    while len(data) < length:
        part = sock.recv(length - len(data))
        if not part:
            raise EOFError("broker prelude ended early")
        data += part
    return data


def main():
    binary = os.environ.get("SMOLVM_E2E_BIN", "target/debug/smolvm")
    if sys.platform not in ("linux", "darwin"):
        raise RuntimeError("this integration check supports Linux and macOS")
    if sys.platform == "linux" and not Path("/dev/kvm").exists():
        raise RuntimeError("this integration check requires /dev/kvm")
    host_home = Path.home()
    default_rootfs = host_home / (
        "Library/Application Support/smolvm/agent-rootfs"
        if sys.platform == "darwin" else ".local/share/smolvm/agent-rootfs"
    )
    token = os.urandom(32)
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(8)
    listener.settimeout(0.2)
    flows, broker_errors = [], []
    done = threading.Event()

    def broker():
        while not done.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            try:
                with stream:
                    stream.settimeout(5)
                    header = read_exact(stream, 75)
                    ip = read_exact(stream, 4 if header[72] == 4 else 16)
                    first = read_exact(stream, int.from_bytes(read_exact(stream, 2), "big"))
                    assert header[:8] == b"SMOLMEG2" and header[8:40] == token
                    assert socket.inet_ntop(socket.AF_INET, ip) == "1.1.1.1"
                    flows.append((header[40:56].hex(), header[56:72].hex(), first))
                    stream.sendall(b"\x02broker-ok\n")
            except Exception as error:
                broker_errors.append(str(error))

    worker = threading.Thread(target=broker, daemon=True)
    worker.start()
    api_port, rollout_port = free_port(), free_port()
    with tempfile.TemporaryDirectory(prefix="sme-", dir="/tmp") as root:
        env = os.environ.copy()
        env.update(
            XDG_CACHE_HOME=root + "/cache",
            XDG_DATA_HOME=root + "/data",
            XDG_CONFIG_HOME=root + "/config",
            SMOLVM_GUEST_ROLLOUT_HOST_PORT=str(rollout_port),
        )
        if sys.platform == "darwin":
            # macOS dirs:: paths follow HOME, while Linux honors XDG directly.
            env["HOME"] = root
        if "SMOLVM_AGENT_ROOTFS" not in env:
            env["SMOLVM_AGENT_ROOTFS"] = str(default_rootfs)
        log_path = Path(root) / "server.log"
        with log_path.open("wb") as log:
            server = subprocess.Popen(
                [binary, "serve", "start", "-l", f"127.0.0.1:{api_port}"],
                env=env,
                stdout=log,
                stderr=subprocess.STDOUT,
            )
            base = f"http://127.0.0.1:{api_port}/api/v1/machines"

            def api(method, path, body=None):
                request = urllib.request.Request(
                    base + path,
                    method=method,
                    data=None if body is None else json.dumps(body).encode(),
                    headers={"Content-Type": "application/json"},
                )
                try:
                    with urllib.request.urlopen(request, timeout=60) as response:
                        return response.status, json.load(response)
                except urllib.error.HTTPError as error:
                    body = error.read().decode()
                    try:
                        body = json.loads(body)
                    except json.JSONDecodeError:
                        pass
                    return error.code, body

            try:
                for _ in range(100):
                    if server.poll() is not None:
                        raise RuntimeError("API server exited before readiness")
                    try:
                        urllib.request.urlopen(f"http://127.0.0.1:{api_port}/health", timeout=0.2).close()
                        break
                    except Exception:
                        time.sleep(0.1)
                else:
                    raise RuntimeError("API server did not become ready")

                assert api("POST", "", {"name": "invalid-rule", "egressRules": [
                    {"transport": "tcp", "cidr": "bad-cidr", "action": "allow"},
                ]})[0] == 400
                assert api("POST", "", {"name": "tsi-rule", "networkBackend": "tsi", "egressRules": [
                    {"transport": "tcp", "action": "deny"},
                ]})[0] == 400

                assert api("POST", "", {"name": "source", "network": True, "allowedCidrs": ["1.1.1.1/32"],
                    "egressRules": [
                        {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 80, "end": 80}, "action": "deny"},
                        {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 443, "end": 443}, "action": "redirect"},
                        {"transport": "tcp", "cidr": "1.1.1.1/32", "ports": {"start": 8443, "end": 8443}, "action": "allow"},
                        {"transport": "udp", "cidr": "1.1.1.1/32", "ports": {"start": 124, "end": 124}, "action": "allow"},
                    ]})[0] == 200
                assert api("POST", "/source/start")[0] == 400
                binding = {"egressInterceptor": {
                    "address": f"127.0.0.1:{listener.getsockname()[1]}",
                    "token": token.hex(), "mediated": True,
                }}
                assert api("POST", "/source/start?branchable=true", binding)[0] == 200

                def guest_flow(name):
                    status, result = api("POST", f"/{name}/exec", {
                        "command": ["sh", "-c", "printf hello | nc -w 2 1.1.1.1 443"],
                    })
                    assert status == 200 and result["exitCode"] == 0 and result["stdout"] == "broker-ok\n", result

                guest_flow("source")
                assert api("POST", "/source/branches", {"name": "child"})[0] == 200
                guest_flow("child")
                assert len(flows) == 2 and not broker_errors, (flows, broker_errors)
                assert flows[0][0] != flows[1][0] and flows[1][1] == flows[0][0], flows
                assert flows[0][2] == flows[1][2] == b"hello", flows

                api("POST", "/source/exec", {"command": ["sh", "-c", "printf deny | nc -w 1 1.1.1.1 80"]})
                api("POST", "/source/exec", {"command": ["sh", "-c", "printf direct | nc -w 1 1.1.1.1 8443"]})
                assert len(flows) == 2, flows

                # These protocols must be denied by the same host boundary.
                api("POST", "/source/exec", {"command": [
                    "sh", "-c", "printf udp | nc -u -w 1 1.1.1.1 123",
                ]})
                api("POST", "/source/exec", {"command": [
                    "sh", "-c", "printf udp | nc -u -w 1 1.1.1.1 124",
                ]})
                api("POST", "/source/exec", {"command": [
                    "ping", "-c", "1", "-W", "1", "1.1.1.1",
                ]})

                status, audit = api("GET", "/source/mediation-events")
                assert status == 200 and any(
                    event["transport"] == "tcp" and event["action"] == "redirect"
                    and event["machineId"] == flows[0][0]
                    for event in audit["events"]
                ), audit
                assert {("udp", "deny"), ("icmp", "deny")} <= {
                    (event["transport"], event["action"]) for event in audit["events"]
                }, audit
                assert {("tcp", "allow", "static_rule"), ("udp", "allow", "local_policy")} <= {
                    (event["transport"], event["action"], event["reason"]) for event in audit["events"]
                }, audit
                assert any(event["transport"] == "tcp" and event["action"] == "deny"
                    and event["destination"] == "to 1.1.1.1:80" for event in audit["events"]), audit
                assert api("POST", "/child/stop")[0] == 200
                assert api("DELETE", "/child")[0] == 200

                # A dead broker may reset the guest flow but must never cause
                # smolvm to dial the original destination as a fallback.
                done.set()
                listener.close()
                worker.join(timeout=1)
                api("POST", "/source/exec", {"command": [
                    "sh", "-c", "printf hello | nc -w 2 1.1.1.1 443",
                ]})
                status, audit = api("GET", "/source/mediation-events")
                assert status == 200 and any(
                    event["transport"] == "tcp"
                    and event["action"] == "deny"
                    and event["reason"] == "broker_unavailable"
                    for event in audit["events"]
                ), audit
                assert api("POST", "/source/stop")[0] == 200
                assert api("POST", "/source/start")[0] == 400
                print("mediated egress API, broker, audit, branch identity, and restart fence: PASS")
            finally:
                for name in ("child", "source"):
                    try:
                        api("POST", f"/{name}/stop")
                        api("DELETE", f"/{name}")
                    except Exception:
                        pass
                server.terminate()
                try:
                    server.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    server.kill()
                    server.wait()
                done.set()
                listener.close()
                worker.join(timeout=1)
        if server.returncode not in (0, -15):
            print(log_path.read_text()[-2000:])


if __name__ == "__main__":
    main()
