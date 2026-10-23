"""External web fingerprinting / content discovery tools.

* ``whatweb``      - technology fingerprinting (http_fingerprint capability).
* ``gobuster_scan``- directory/content discovery against a bounded wordlist.
* ``wafw00f``      - WAF fingerprinting (http_waf_detect capability).

Each degrades to ``unavailable`` when its binary is missing, so the pure-Python
posture tools (``http_posture``, ``web_content``, ``http_waf_detect``) remain the
always-available baseline.
"""

from __future__ import annotations

import json
import re
import secrets
import subprocess
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

from app.config import settings
from app.net.http import request_with_retries
from app.tools.base import (
    EffectClass,
    ToolContext,
    ToolResult,
    evidence,
    failure,
    run_command,
    unavailable,
    which,
)
from app.tools.registry import tool

_GOBUSTER_LINE = re.compile(
    r"^(?P<path>\S+)\s+\(Status:\s*(?P<status>\d+)\)(?:\s*\[Size:\s*(?P<size>\d+)\])?"
)
_GOBUSTER_PROGRESS = re.compile(r"(?i)progress:\s*(?P<done>\d+)\s*/\s*(?P<total>\d+)")
_GOBUSTER_VERSION = re.compile(r"(?i)version\s+(\d+\.\d+(?:\.\d+)?)")
_GOBUSTER_WILDCARD_HINT = "matches the provided options for non existing urls"
_WAFW00F_BEHIND = re.compile(r"is behind\s+(?P<name>.+?)(?:\s*\(|$)", re.IGNORECASE)

_FALLBACK_WORDS = ["admin", "login", "api", "backup", "config", "uploads", "robots.txt", "sitemap.xml"]


def _load_wordlist() -> list[str]:
    path = settings.wordlist_dir / "common.txt"
    if not path.exists():
        return _FALLBACK_WORDS
    return [
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]


def _temp_file(suffix: str) -> Path:
    handle = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    handle.close()
    return Path(handle.name)


def _parse_whatweb_json(text: str) -> dict:
    """Parse WhatWeb JSON-lines output into ``{plugins, summary}``."""
    plugins: dict[str, dict] = {}
    targets: list[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if item.get("target"):
            targets.append(item["target"])
        for name, detail in (item.get("plugins") or {}).items():
            info: dict = {}
            if isinstance(detail, dict):
                for key in ("version", "string"):
                    value = detail.get(key)
                    if isinstance(value, list) and value:
                        info[key] = value[0]
                    elif isinstance(value, str):
                        info[key] = value
            plugins[name] = info
    return {"plugins": plugins, "targets": targets, "technologies": sorted(plugins)}


def _normalise_gobuster_path(raw: str) -> str:
    """Accept ``/admin``, ``admin`` and ``https://host/admin`` output forms."""
    value = raw.strip()
    if "://" in value:
        value = urlsplit(value).path or "/"
    if not value.startswith("/"):
        value = "/" + value
    return value


def _parse_gobuster(stdout: str) -> list[dict]:
    found: list[dict] = []
    for line in stdout.splitlines():
        match = _GOBUSTER_LINE.match(line.strip())
        if match:
            found.append(
                {
                    "path": _normalise_gobuster_path(match.group("path")),
                    "status": int(match.group("status")),
                    "size": int(match.group("size")) if match.group("size") else None,
                }
            )
    return found


def _gobuster_version(executable: str) -> str | None:
    try:
        completed = run_command([executable, "--version"], timeout=5)
    except Exception:
        return None
    match = _GOBUSTER_VERSION.search(f"{completed.stdout}\n{completed.stderr}")
    return match.group(1) if match else None


def _gobuster_progress(stdout: str) -> tuple[int, int | None]:
    """Return ``(candidates_attempted, declared_total)`` from progress output."""
    attempted = 0
    total: int | None = None
    for match in _GOBUSTER_PROGRESS.finditer(stdout):
        attempted = max(attempted, int(match.group("done")))
        total = int(match.group("total"))
    return attempted, total


def _tail(value: str | bytes | None, limit: int = 1200) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return value.strip()[-limit:]


def _parse_wafw00f(stdout: str) -> dict:
    cleaned = stdout.strip()
    try:
        raw = json.loads(cleaned)
        if isinstance(raw, list) and raw:
            item = raw[0]
            return {
                "detected": bool(item.get("detected")),
                "firewall": item.get("firewall") or "None",
                "manufacturer": item.get("manufacturer") or "",
            }
    except (ValueError, TypeError):
        pass
    match = _WAFW00F_BEHIND.search(stdout)
    if match:
        return {"detected": True, "firewall": match.group("name").strip(), "manufacturer": ""}
    return {"detected": False, "firewall": "None", "manufacturer": ""}


@tool(
    name="whatweb",
    description="Web technology fingerprinting with WhatWeb.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_fingerprint",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=45,
)
def whatweb(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    safe_command = f"whatweb --color=never {url}"
    if which("whatweb") is None:
        return unavailable("whatweb", "WhatWeb is not installed.", command=safe_command)

    report = _temp_file(".json")
    command = ["whatweb", "--color=never", "--log-json", str(report), url]
    started = time.perf_counter()
    try:
        run_command(command, timeout=settings.http_timeout * 4)
    except Exception as exc:
        report.unlink(missing_ok=True)
        return failure("whatweb", f"WhatWeb did not complete: {type(exc).__name__}", command=safe_command)

    try:
        parsed = _parse_whatweb_json(report.read_text(encoding="utf-8", errors="replace"))
    finally:
        report.unlink(missing_ok=True)

    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="whatweb",
        status="ok" if parsed["technologies"] else "partial",
        summary=f"{len(parsed['technologies'])} technolog(ies) fingerprinted.",
        data=parsed,
        evidence=[evidence("whatweb", name) for name in parsed["technologies"][:12]],
        command=safe_command,
        note="Fingerprinting only; no exploitation.",
        duration_ms=duration,
    )


@tool(
    name="gobuster_scan",
    description="Directory/content discovery with Gobuster (bounded wordlist).",
    category="CONTENT",
    effect_class=EffectClass.ACTIVE_PROBE,
    capability="web_content",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=62,
)
def gobuster_scan(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url.rstrip("/")
    words = [word for word in (ctx.option("content_words") or _load_wordlist()) if str(word).strip()]
    safe_command = f"gobuster dir -u {url} -w common.txt ({len(words)} words)"

    if not url.startswith(("http://", "https://")):
        return failure("gobuster", "Target must be an http(s) base URL.", command=safe_command)
    if not words:
        return failure("gobuster", "No candidate words were supplied.", command=safe_command)
    executable = which("gobuster")
    if executable is None:
        return unavailable("gobuster", "Gobuster is not installed.", command=safe_command)
    version = _gobuster_version(executable)

    # A base probe distinguishes "the site returns a uniform access-control
    # page" from real path discovery without making extra aggressive requests.
    base = request_with_retries(url, method="GET", retries=0)
    base_status = base.status_code
    base_class = base.response_class.value
    edge_indicators = base.edge_indicators
    suspicious_base = base_status in {401, 403, 429} or base.edge_likely or base_status is None

    # Gobuster aborts before scanning when a random path returns the same
    # deny/error page as the target (its wildcard guard). A single bounded
    # probe captures that page length so it can be excluded without bypassing
    # access controls; 403 responses are still recorded as inaccessible.
    probe_url = f"{url}/{secrets.token_hex(8)}"
    probe = request_with_retries(probe_url, method="GET", retries=0)
    uniform_statuses = {401, 403, 429, 500, 502, 503, 504}
    exclude_length = (
        probe.body_length
        if probe.status_code in uniform_statuses and probe.body_length > 0
        else None
    )

    wordlist = _temp_file(".txt")
    wordlist.write_text("\n".join(str(word) for word in words), encoding="utf-8")
    command = [
        executable, "dir", "-u", url, "-w", str(wordlist),
        "-q", "-t", "20", "--timeout", "5s", "--no-progress",
    ]
    if exclude_length is not None:
        command.extend(["--exclude-length", str(exclude_length)])
    safe_arguments = [
        Path(executable).name, "dir", "-u", url, "-w", "common.txt",
        "-q", "-t", "20", "--timeout", "5s", "--no-progress",
    ]
    if exclude_length is not None:
        safe_arguments.extend(["--exclude-length", str(exclude_length)])

    started = time.perf_counter()
    completed: subprocess.CompletedProcess[str] | None = None
    timed_out = False
    failure_error: str | None = None
    try:
        completed = run_command(command, timeout=settings.nmap_timeout)
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        completed = subprocess.CompletedProcess(
            args=command,
            returncode=None,
            stdout=exc.stdout or "",
            stderr=exc.stderr or "",
        )
        failure_error = f"TimeoutExpired after {exc.timeout}s"
    except Exception as exc:
        failure_error = f"{type(exc).__name__}: {exc}"
    finally:
        wordlist.unlink(missing_ok=True)
        duration = int((time.perf_counter() - started) * 1000)

    raw_stdout = completed.stdout if completed else ""
    raw_stderr = completed.stderr if completed else ""
    stdout = _tail(raw_stdout)
    stderr = _tail(raw_stderr)
    found = _parse_gobuster(raw_stdout) if completed else []
    attempted_progress, declared_total = _gobuster_progress(raw_stdout)

    valid = [item for item in found if 200 <= int(item["status"]) < 400]
    rejected = [item for item in found if int(item["status"]) in {401, 403, 429}]
    server_errors = [item for item in found if int(item["status"]) >= 500]

    returncode = completed.returncode if completed else None
    failure_reason: str | None = None
    failure_stage: str | None = None
    if failure_error and completed is None:
        failure_stage = (
            "preflight"
            if failure_error.startswith(("FileNotFoundError", "PermissionError"))
            else "execution"
        )
        failure_reason = "process_not_started"
    elif timed_out:
        failure_stage = "execution"
        failure_reason = "timeout"
    elif returncode not in (0, None):
        failure_stage = "execution"
        combined = f"{stdout}\n{stderr}".lower()
        if _GOBUSTER_WILDCARD_HINT in combined or "wildcard" in combined:
            failure_reason = "wildcard_or_uniform_response"
            failure_stage = "preflight"
        elif any(token in combined for token in ("no such host", "connection refused", "i/o timeout")):
            failure_reason = "network_error"
        elif "wordlist" in combined:
            failure_reason = "wordlist_error"
        elif "error" in combined or raw_stderr:
            failure_reason = "process_error"
        else:
            failure_reason = "nonzero_exit"
    elif returncode == 0:
        failure_stage = "completed"

    if timed_out:
        attempted = attempted_progress
        untested = max(0, len(words) - attempted)
    elif failure_reason == "wildcard_or_uniform_response" and not found:
        attempted = 0
        untested = len(words)
    else:
        attempted = len(words) if completed is not None else attempted_progress
        untested = max(0, (declared_total or len(words)) - attempted)

    # A uniform access-control/CDN response is not route discovery.
    statuses = {int(item["status"]) for item in found}
    uniform = bool(found) and len(statuses) == 1 and next(iter(statuses)) in {401, 403, 429, 500, 502, 503}
    suspicious_uniform = uniform and suspicious_base
    confirmed = [] if suspicious_uniform else valid

    if failure_error and completed is None:
        status = "failed"
        summary = f"Gobuster did not run: {failure_error}"
    elif timed_out:
        status = "partial" if found else "failed"
        summary = (
            f"Gobuster timed out after {attempted}/{len(words)} candidate(s); "
            f"{len(found)} response(s) were preserved."
        )
    elif failure_reason == "wildcard_or_uniform_response" and not found:
        status = "failed"
        summary = (
            "Gobuster did not scan: a random path returned HTTP "
            f"{probe.status_code} with a uniform "
            f"{exclude_length or probe.body_length}-byte response (wildcard/access-control page). "
            "No route discovery result is claimed."
        )
    elif returncode not in (0, None):
        status = "partial" if found else "failed"
        summary = (
            f"Gobuster exited with code {returncode} ({failure_reason or 'unknown'}); "
            f"{len(found)} response(s) preserved."
        )
    else:
        status = "ok"
        if found:
            summary = f"{len(found)} path(s) discovered across {len(words)} candidate(s)."
        else:
            summary = f"Gobuster completed cleanly with zero responses across {len(words)} candidate(s)."

    data = {
        "paths": found,
        "confirmed_paths": confirmed,
        "tested": len(words),
        "attempted": attempted,
        "untested": untested,
        "valid_responses": len(valid),
        "rejected_responses": len(rejected),
        "server_error_responses": len(server_errors),
        "returncode": returncode,
        "timed_out": timed_out,
        "completed": returncode == 0,
        "process_started": completed is not None,
        "zero_result_success": status == "ok" and not found,
        "failure_stage": failure_stage,
        "failure_reason": failure_reason,
        "target_url": url,
        "executable": executable,
        "version": version,
        "arguments": safe_arguments,
        "exclude_length": exclude_length,
        "random_probe_url": probe_url,
        "random_probe_status": probe.status_code,
        "random_probe_response_class": probe.response_class.value,
        "random_probe_length": probe.body_length,
        "duration_ms": duration,
        "stdout_tail": stdout,
        "stderr_tail": stderr,
        "base_status": base_status,
        "base_response_class": base_class,
        "base_edge_indicators": edge_indicators,
        "uniform_response": uniform,
        "suspicious_uniform": suspicious_uniform,
    }
    return ToolResult(
        tool="gobuster",
        status=status,
        summary=summary,
        data=data,
        evidence=[
            evidence(
                "gobuster",
                f"base URL: HTTP {base_status} ({base_class})"
                + (f"; edge indicators: {', '.join(edge_indicators)}" if edge_indicators else ""),
                url=url,
                status=base_status,
                response_class=base_class,
            ),
            evidence(
                "gobuster",
                f"random-path probe: HTTP {probe.status_code} ({probe.response_class.value}), "
                f"{probe.body_length} bytes"
                + (f"; excluded length {exclude_length}" if exclude_length else ""),
                url=probe_url,
                status=probe.status_code,
                response_class=probe.response_class.value,
                outcome="wildcard/access-control page" if exclude_length else "probe",
            ),
        ]
        + [
            evidence(
                "gobuster",
                f"{item['path']} -> HTTP {item['status']}"
                + (" (uniform access-control response; not confirmed)" if suspicious_uniform else ""),
                url=url + item["path"],
                status=item["status"],
            )
            for item in found[:12]
        ],
        command=" ".join(safe_arguments),
        note=(
            "Directory discovery only; no exhaustive brute force. "
            "Zero results do not mean no paths exist. Uniform 401/403/429 or CDN "
            "responses are recorded as inaccessible, not as discovered routes. "
            "A uniform deny-page length is excluded so the scan can run without "
            "bypassing access controls; excluded responses are not reported as routes."
        ),
        duration_ms=duration,
        error=(
            failure_error
            or (
                f"exit {returncode}: {failure_reason}"
                if returncode not in (0, None)
                else None
            )
        ),
    )


@tool(
    name="wafw00f",
    description="Web application firewall detection with wafw00f.",
    category="WEB",
    effect_class=EffectClass.PASSIVE,
    capability="http_waf_detect",
    priority=40,
    requires=("base_url",),
    profiles=("web", "full"),
    order=66,
)
def wafw00f(ctx: ToolContext) -> ToolResult:
    url = ctx.target.base_url
    safe_command = f"wafw00f {url}"
    if which("wafw00f") is None:
        return unavailable("wafw00f", "wafw00f is not installed.", command=safe_command)

    command = ["wafw00f", url, "-f", "json"]
    started = time.perf_counter()
    try:
        completed = run_command(command, timeout=settings.http_timeout * 4)
    except Exception as exc:
        return failure("wafw00f", f"wafw00f did not complete: {type(exc).__name__}", command=safe_command)

    parsed = _parse_wafw00f(completed.stdout)
    duration = int((time.perf_counter() - started) * 1000)
    return ToolResult(
        tool="wafw00f",
        status="ok",
        summary=(f"WAF: {parsed['firewall']}" if parsed["detected"] else "No WAF detected."),
        data=parsed,
        evidence=[evidence("wafw00f", f"detected={parsed['detected']} firewall={parsed['firewall']}")],
        command=safe_command,
        note="Detection only; no bypass attempts.",
        duration_ms=duration,
    )
