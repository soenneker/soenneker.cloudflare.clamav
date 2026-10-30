"""Exercise the published image using real ClamAV, including daemon recovery."""
import hashlib
import http.client
import io
import json
import os
import secrets
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid
import zipfile

image = sys.argv[1] if len(sys.argv) > 1 else "soenneker-cloudflare-clamav:test"
name = "clamav-smoke-" + str(uuid.uuid4())
key = secrets.token_urlsafe(40)

def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()

def request(path, data=None, authenticated=True):
    headers = {"Authorization": "Bearer " + key} if authenticated else {}
    if data is not None: headers["Content-Type"] = "application/octet-stream"
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=330) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)

def ready(deadline=420):
    until = time.monotonic() + deadline
    while time.monotonic() < until:
        try:
            status, value = request("/ready")
            if status == 200 and value["ready"]: return value
        except (OSError, ValueError): pass
        time.sleep(2)
    raise AssertionError("Scanner readiness deadline exceeded")

def scan(data, verdict):
    status, value = request("/scan", data)
    assert status == 200, (status, value)
    assert value["verdict"] == verdict, value
    assert value["clean"] == (verdict == "clean"), value
    assert value["sha256"] == hashlib.sha256(data).hexdigest(), value
    assert value["signatureVersion"] and value["scanId"], value
    print("Verified", verdict, value["reason"], flush=True)

try:
    docker("run", "-d", "--name", name, "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
           "--memory=4g", "--cpus=2", "--tmpfs", "/data:rw,noexec,nosuid,size=2g,uid=1654,gid=1654",
           "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m", "-p", "127.0.0.1::8080",
           "-e", "Scanner__ApiKey=" + key, image)
    port = docker("port", name, "8080/tcp").split(":")[-1]
    base = "http://127.0.0.1:" + port
    health = ready()
    print("Ready:", health, flush=True)
    assert docker("exec", name, "id", "-u") != "0"
    assert request("/scan", b"clean", authenticated=False)[0] == 401
    scan(b"ordinary clean text", "clean")
    # EICAR is a harmless antivirus test pattern, kept in memory only.
    eicar = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    scan(eicar, "infected")
    archive = io.BytesIO()
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped:
        zipped.writestr("test.txt", eicar)
    scan(archive.getvalue(), "infected")
    import pyzipper
    encrypted = io.BytesIO()
    with pyzipper.AESZipFile(encrypted, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zipped:
        zipped.setpassword(b"test-only-password")
        zipped.writestr("private.txt", b"encrypted content")
    scan(encrypted.getvalue(), "inconclusive")
    nested = b"payload"
    for i in range(20):
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as zipped: zipped.writestr("nested.zip", nested)
        nested = archive.getvalue()
    scan(nested, "inconclusive")
    # Unknown content length must still be bounded by the server's counted upload limit.
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=30)
    connection.putrequest("POST", "/scan")
    connection.putheader("Authorization", "Bearer " + key)
    connection.putheader("Transfer-Encoding", "chunked")
    connection.endheaders()
    try:
        block = b"x" * 65536
        for _ in range(1601): connection.send(b"10000\r\n" + block + b"\r\n")
        connection.send(b"0\r\n\r\n")
    except (BrokenPipeError, ConnectionResetError): pass
    assert connection.getresponse().status == 413
    connection.close()
    # Drop a partial upload and verify that its file is removed.
    connection = http.client.HTTPConnection("127.0.0.1", int(port), timeout=10)
    connection.putrequest("POST", "/scan")
    connection.putheader("Authorization", "Bearer " + key)
    connection.putheader("Content-Length", "1048576")
    connection.endheaders(); connection.send(b"partial upload"); connection.close()
    time.sleep(2)
    leftovers = docker("exec", name, "sh", "-c", "find /data -maxdepth 1 -name '*.scan' -print")
    assert not leftovers, leftovers
    docker("exec", name, "sh", "-c", 'for p in /proc/[0-9]*/comm; do read n < "$p"; if [ "$n" = clamd ]; then pid=${p#/proc/}; kill -9 ${pid%/comm}; fi; done')
    assert request("/ready")[0] == 503
    ready(90)
    scan(b"clean after daemon restart", "clean")
    print("Container smoke tests passed", flush=True)
except Exception:
    print(docker("logs", "--tail", "120", name), file=sys.stderr)
    raise
finally:
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL)
