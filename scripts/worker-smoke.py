"""Exercise the real local Worker, D1, R2, Queue, and Docker container together."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import uuid

if os.name == "nt":
    raise SystemExit("Wrangler container development requires Linux or macOS. Run this check in the Linux CI workflow or a configured WSL environment.")

root = Path(__file__).resolve().parents[1]
(root / "artifacts").mkdir(exist_ok=True)
key = secrets.token_urlsafe(40)
name = "clamav-e2e-" + str(uuid.uuid4())
with socket.socket() as port_socket:
    port_socket.bind(("127.0.0.1", 0)); port = port_socket.getsockname()[1]
base = f"http://127.0.0.1:{port}"
command = ["node", str(root / "worker/node_modules/wrangler/bin/wrangler.js")]
process = None

def request(path, data=None, submission=None):
    headers = {"Authorization": "Bearer " + key}
    if data is not None:
        headers.update({"Content-Type": "application/octet-stream", "Idempotency-Key": submission or str(uuid.uuid4()), "X-Content-SHA256": hashlib.sha256(data).hexdigest()})
    try:
        with urllib.request.urlopen(urllib.request.Request(base+path, data=data, headers=headers), timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error: return error.code, json.load(error)

def wait_host():
    for _ in range(120):
        if process.poll() is not None: raise RuntimeError("Local Worker exited")
        try:
            if request("/health")[0] == 200: return
        except OSError: pass
        time.sleep(1)
    raise RuntimeError("Local Worker did not start")

def wait_job(id):
    until = time.monotonic()+600
    while time.monotonic() < until:
        status, job = request("/scan/jobs/"+id)
        assert status == 200, (status, job)
        if job["status"] in ("completed", "failed"): return job
        time.sleep(2)
    raise AssertionError("Job completion deadline exceeded")

def stop():
    global process
    if process is not None and process.poll() is None:
        if os.name == "nt": subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else: os.killpg(process.pid, signal.SIGTERM)
        try: process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            if os.name != "nt": os.killpg(process.pid, signal.SIGKILL)
            else: process.kill()
    process = None

with tempfile.TemporaryDirectory(prefix="worker-smoke-", dir=root/"artifacts") as temporary:
    directory = Path(temporary).resolve()
    assert directory.is_relative_to((root/"artifacts").resolve())
    config = json.loads((root/"worker/wrangler.jsonc").read_text())
    config["name"] = name
    config["main"] = str(root/"worker/src/index.ts")
    config["containers"][0]["image"] = str(root/"Dockerfile")
    config["d1_databases"][0]["database_id"] = "00000000-0000-0000-0000-000000000001"
    config["d1_databases"][0]["migrations_dir"] = str(root/"worker/migrations")
    (directory/"wrangler.json").write_text(json.dumps(config))
    (directory/".dev.vars").write_text("SCANNER_API_KEY="+key+"\n")
    common = ["--config", str(directory/"wrangler.json"), "--persist-to", str(directory/"state")]
    environment = {**os.environ, "WRANGLER_SEND_METRICS": "false", "CI": "true"}
    logfile = directory/"worker.log"
    with logfile.open("w") as output:
        try:
            subprocess.run(command+["d1", "migrations", "apply", "scanner-jobs", "--local", *common], cwd=root/"worker", env=environment, input="y\n", text=True, stdout=output, stderr=output, check=True)
            def start():
                global process
                process = subprocess.Popen(command+["dev", "--local", "--port", str(port), "--test-scheduled", "--show-interactive-dev-session=false", *common], cwd=root/"worker", env=environment, stdout=output, stderr=output,
                    start_new_session=os.name != "nt", creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == "nt" else 0)
                wait_host()
            start()
            submission = str(uuid.uuid4())
            status, accepted = request("/scan/jobs", b"durable clean test content", submission)
            assert status == 202, (status, accepted)
            job = wait_job(accepted["id"])
            assert job["status"] == "completed" and job["result"]["clean"], job
            assert request("/scan/jobs", b"durable clean test content", submission)[1]["id"] == job["id"]
            print("Worker, R2, D1, Queue, and native scanner completed a durable scan", flush=True)
            # A restart must preserve the job and its idempotency key.
            stop(); start()
            persisted = request("/scan/jobs/"+job["id"])[1]
            assert persisted["result"]["sha256"] == job["result"]["sha256"]
            assert request("/scan/jobs", b"durable clean test content", submission)[1]["id"] == job["id"]
            print("Durable result and submission identity survived Worker restart", flush=True)
        except Exception:
            output.flush()
            print(logfile.read_text(errors="replace")[-18000:], file=sys.stderr)
            raise
        finally:
            stop()
            # Only remove containers built for this unique smoke-test Worker.
            ids = subprocess.check_output(["docker", "ps", "-aq", "--filter", "ancestor="+name+"-scannercontainer"], text=True).split()
            if ids: subprocess.run(["docker", "rm", "-f", *ids], check=False, stdout=subprocess.DEVNULL)
