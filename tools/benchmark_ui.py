#!/usr/bin/env python3
import html
import json
import mimetypes
import re
import socket
import subprocess
from datetime import datetime
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlencode, unquote, urlsplit


ROOT_DIR = Path(__file__).resolve().parents[1]
BENCHMARKS_DIR = ROOT_DIR / "benchmarks"
ASSETS_DIR = ROOT_DIR / "assets"


def get_host_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return "127.0.0.1"


def run_compose(benchmark_dir: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", *args],
        cwd=benchmark_dir,
        capture_output=True,
        text=True,
        check=False,
    )


PORT_MAPPING_PATTERN = re.compile(r'(?P<quote>["\']?)(?P<host>\d+):(?P<container>\d+)(?P=quote)')


def parse_port_from_compose(compose_path: Path) -> int | None:
    content = compose_path.read_text(encoding="utf-8")
    match = re.search(r'["\']?(\d+):\d+["\']?', content)
    if not match:
        return None
    return int(match.group(1))


def update_compose_port(compose_path: Path, new_port: int) -> tuple[bool, str]:
    content = compose_path.read_text(encoding="utf-8")

    def replacer(match: re.Match[str]) -> str:
        quote = match.group("quote")
        container_port = match.group("container")
        return f"{quote}{new_port}:{container_port}{quote}"

    updated, count = PORT_MAPPING_PATTERN.subn(replacer, content, count=1)
    if count == 0:
        return False, "Could not find a port mapping in docker-compose.yml."

    compose_path.write_text(updated, encoding="utf-8")
    return True, f"Port updated to {new_port}."


@dataclass
class Benchmark:
    benchmark_id: str
    title: str
    path: Path
    port: int | None


@dataclass
class BenchmarkRow:
    benchmark_id: str
    name: str
    port: int | None
    ip: str
    running: bool
    has_readme: bool

    @property
    def url(self) -> str:
        if self.port is None:
            return f"http://{self.ip}"
        return f"http://{self.ip}:{self.port}"


def discover_benchmarks() -> list[Benchmark]:
    benchmarks: list[Benchmark] = []
    for directory in sorted(BENCHMARKS_DIR.glob("APY-*-*")):
        compose_path = directory / "docker-compose.yml"
        benchmark_json = directory / "benchmark.json"
        if not compose_path.exists():
            continue

        title = directory.name
        if benchmark_json.exists():
            try:
                metadata = json.loads(benchmark_json.read_text(encoding="utf-8"))
                title = metadata.get("name", title)
            except json.JSONDecodeError:
                pass

        benchmarks.append(
            Benchmark(
                benchmark_id=directory.name,
                title=title,
                path=directory,
                port=parse_port_from_compose(compose_path),
            ),
        )
    return benchmarks


def benchmark_running(benchmark: Benchmark) -> bool:
    result = run_compose(benchmark.path, "ps", "--status", "running", "--services")
    if result.returncode != 0:
        return False
    return bool(result.stdout.strip())


def start_benchmark(benchmark: Benchmark, port_override: int | None = None) -> tuple[bool, str]:
    if port_override is not None:
        compose_path = benchmark.path / "docker-compose.yml"
        ok, msg = update_compose_port(compose_path, port_override)
        if not ok:
            return False, msg

    flag = f"flag{{{benchmark.benchmark_id}}}"
    build_result = run_compose(
        benchmark.path,
        "build",
        "--build-arg",
        f"FLAG={flag}",
        "--build-arg",
        f"flag={flag}",
    )
    if build_result.returncode != 0:
        return False, (build_result.stderr or build_result.stdout or "Build failed").strip()

    up_result = run_compose(benchmark.path, "up", "-d")
    if up_result.returncode != 0:
        return False, (up_result.stderr or up_result.stdout or "Compose up failed").strip()

    return True, f"{benchmark.benchmark_id} started."


def stop_benchmark(benchmark: Benchmark) -> tuple[bool, str]:
    down_result = run_compose(benchmark.path, "down")
    if down_result.returncode != 0:
        return False, (down_result.stderr or down_result.stdout or "Compose down failed").strip()
    return True, f"{benchmark.benchmark_id} stopped."


def detect_logo_url() -> str:
    if not ASSETS_DIR.exists():
        return ""

    image_files = [
        path
        for path in ASSETS_DIR.iterdir()
        if path.is_file() and path.suffix.lower() in {".png", ".jpg", ".jpeg", ".svg", ".webp", ".ico"}
    ]
    if not image_files:
        return ""

    preferred = sorted(image_files, key=lambda p: ("logo" not in p.name.lower(), p.name.lower()))[0]
    return f"/assets/{preferred.name}"


def safe_asset_path(asset_name: str) -> Path | None:
    candidate = (ASSETS_DIR / asset_name).resolve()
    try:
        candidate.relative_to(ASSETS_DIR.resolve())
    except ValueError:
        return None

    if not candidate.exists() or not candidate.is_file():
        return None
    return candidate


def build_rows() -> list[BenchmarkRow]:
    ip = get_host_ip()
    rows: list[BenchmarkRow] = []
    for benchmark in discover_benchmarks():
        rows.append(
            BenchmarkRow(
                benchmark_id=benchmark.benchmark_id,
                name=benchmark.title,
                port=benchmark.port,
                ip=ip,
                running=benchmark_running(benchmark),
                has_readme=(benchmark.path / "README.md").exists(),
            ),
        )
    return rows


def safe_benchmark_readme_path(benchmark_id: str) -> Path | None:
    benchmark_dir = (BENCHMARKS_DIR / benchmark_id).resolve()
    try:
        benchmark_dir.relative_to(BENCHMARKS_DIR.resolve())
    except ValueError:
        return None

    readme_path = benchmark_dir / "README.md"
    if not readme_path.exists() or not readme_path.is_file():
        return None
    return readme_path


class DashboardHandler(BaseHTTPRequestHandler):
    def _send_html(self, status: int, page_html: str) -> None:
        payload = page_html.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, text: str, content_type: str) -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _send_file(self, status: int, file_path: Path) -> None:
        payload = file_path.read_bytes()
        mime_type, _ = mimetypes.guess_type(str(file_path))
        self.send_response(status)
        self.send_header("Content-Type", mime_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _redirect(self, message: str, kind: str = "success") -> None:
        params = urlencode({"msg": message, "kind": kind})
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", f"/?{params}")
        self.end_headers()

    def _dashboard_html(self, msg: str = "", kind: str = "success") -> str:
        rows = build_rows()
        total = len(rows)
        running = sum(1 for row in rows if row.running)
        stopped = total - running
        logo_url = detect_logo_url()
        generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        run_ratio = int((running / total) * 100) if total else 0

        row_html = []
        for row in rows:
            state_class = "running" if row.running else "stopped"
            openapi_url = f"{row.url.rstrip('/')}/openapi.json"
            readme_button_html = ""
            if row.has_readme:
                readme_button_html = (
                    f'<button class="readme-btn" type="button" data-readme-id="{html.escape(row.benchmark_id)}" '
                    f'data-readme-name="{html.escape(row.name)}">README</button>'
                )
            start_controls_html = ""
            port_cell_html = ""
            if row.running:
                port_cell_html = f'<span class="mono">{row.port if row.port is not None else "-"}</span>'
                start_controls_html = (
                    f'<form method="post" action="/actions/{html.escape(row.benchmark_id)}/stop">'
                    '<button class="state-btn running" type="submit">Stop</button>'
                    "</form>"
                )
            else:
                port_value = str(row.port) if row.port is not None else ""
                port_display = f"Port {port_value}" if port_value else "Port -"
                port_cell_html = (
                    f'<div class="port-inline-editor" data-benchmark-id="{html.escape(row.benchmark_id)}">'
                    f'<span class="port-chip mono" data-port-chip>{html.escape(port_display)}</span>'
                    f'<button class="port-edit-btn" type="button" data-edit-port data-benchmark-id="{html.escape(row.benchmark_id)}" data-benchmark-name="{html.escape(row.name)}" data-current-port="{html.escape(port_value)}" aria-label="Edit port">'
                    '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M3 17.25V21h3.75L17.81 9.94l-3.75-3.75L3 17.25zm2.92 2.83H5v-.92l8.06-8.06.92.92L5.92 20.08zm12.95-12.95-.92.92-.92-.92.92-.92.92.92zM20.71 7.04a1 1 0 0 0 0-1.41L18.37 3.3a1 1 0 0 0-1.41 0l-1.13 1.13 3.75 3.75 1.13-1.14z"/></svg>'
                    "</button>"
                    "</div>"
                )
                start_controls_html = (
                    f'<form method="post" action="/actions/{html.escape(row.benchmark_id)}/start" class="start-form" data-start-form data-benchmark-id="{html.escape(row.benchmark_id)}">'
                    f'<input type="hidden" name="port" value="{html.escape(port_value)}" data-port-hidden />'
                    '<button class="state-btn stopped" type="submit">Start</button>'
                    "</form>"
                )

            row_html.append(
                f"""
                <tr
                  data-running="{str(row.running).lower()}"
                  data-id="{html.escape(row.benchmark_id)}"
                  data-name="{html.escape(row.name)}"
                  data-port="{row.port if row.port is not None else 0}"
                  data-status="{1 if row.running else 0}"
                  data-url="{html.escape(row.url)}"
                >
                  <td class="mono td-id">{html.escape(row.benchmark_id)}</td>
                  <td class="td-name">{html.escape(row.name)}</td>
                  <td class="td-port">{port_cell_html}</td>
                  <td class="td-status"><span class="pill {state_class}">{'Running' if row.running else 'Stopped'}</span></td>
                  <td class="mono td-url">
                    <span class="url-text">{html.escape(row.url)}</span>
                    <a class="url-link openapi-link" href="{html.escape(openapi_url)}" target="_blank" rel="noopener noreferrer">/openapi.json</a>
                  </td>
                  <td class="td-actions">
                    <div class="actions-cell">
                      {readme_button_html}
                      <button class="copy-btn" type="button" data-url="{html.escape(row.url)}">Copy URL</button>
                      <a class="open-btn" href="{html.escape(openapi_url)}" target="_blank" rel="noopener noreferrer">Open</a>
                      {start_controls_html}
                    </div>
                  </td>
                </tr>
                """,
            )

        notice_html = ""
        if msg:
            safe_kind = "error" if kind == "error" else "success"
            notice_html = f'<p class="notice {safe_kind}">{html.escape(msg)}</p>'

        logo_tag = f'<img class="logo" src="{html.escape(logo_url)}" alt="ApyGuard logo" />' if logo_url else ""

        return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ApyGuard Benchmarks Dashboard</title>
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap" rel="stylesheet" />
  <style>
    :root {{
      --background: #f9fafb;
      --foreground: #1e293b;
      --border: #e5e7eb;
      --primary: #3b82f6;
      --secondary: #10b981;
      --hover-color: #f1f5f9;
      --green: #10b981;
      --dark-green: #059669;
      --light: #e2e8f0;
      --error: #b91c1c;
      --white: #ffffff;
      --card: rgba(255, 255, 255, 0.9);
      --line: var(--border);
      --line-soft: #eef2f7;
      --text: var(--foreground);
      --muted: #64748b;
      --brand: var(--primary);
      --brand-strong: #2563eb;
      --danger: var(--error);
      --ok: var(--secondary);
      --shadow: 0 14px 30px rgba(15, 23, 42, 0.08);
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      color: var(--text);
      font-family: "Inter", "Segoe UI", Arial, sans-serif;
      background:
        radial-gradient(circle at 12% 22%, rgba(59, 130, 246, 0.14) 0, transparent 22rem),
        radial-gradient(circle at 85% -8%, rgba(16, 185, 129, 0.18) 0, transparent 26rem),
        linear-gradient(130deg, var(--background), #f1f5f9);
      min-height: 100vh;
    }}
    .page {{
      max-width: 1440px;
      margin: 0 auto;
      padding: 24px clamp(4px, 0.5vw, 8px) 48px;
    }}
    .hero {{
      display: flex; flex-wrap: wrap; gap: 16px; justify-content: space-between; align-items: center;
      border: 1px solid var(--line); border-radius: 18px; background: var(--card);
      padding: 16px 18px;
      box-shadow: var(--shadow);
    }}
    .brand {{ display: flex; align-items: center; gap: 12px; }}
    .logo {{ width: 58px; height: 58px; object-fit: contain; border-radius: 14px; background: var(--white); border: 1px solid var(--border); padding: 6px; }}
    .eyebrow {{ margin: 0; color: var(--muted); font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: .08em; }}
    h1 {{ margin: 2px 0 2px; font-size: clamp(1.2rem, 2.8vw, 1.85rem); }}
    .meta {{ margin: 0; color: var(--muted); font-size: .83rem; }}
    .hero-actions {{ display: flex; gap: 8px; flex-wrap: wrap; }}
    button {{
      border: none; cursor: pointer; border-radius: 10px; font-family: inherit; font-weight: 600;
      padding: 10px 14px;
      transition: transform .12s ease, box-shadow .12s ease, background-color .12s ease;
    }}
    button:hover {{ transform: translateY(-1px); box-shadow: 0 6px 14px rgba(15, 23, 42, 0.14); }}
    .refresh {{ background: var(--white); border: 1px solid var(--border); color: var(--foreground); }}
    .start-all {{ background: var(--brand); color: white; }}
    .stop-all {{ background: var(--error); color: white; }}
    .subbar {{
      margin-top: 12px; display: flex; justify-content: space-between; gap: 12px; flex-wrap: wrap;
      border: 1px solid var(--line); border-radius: 14px; background: var(--card); padding: 11px 12px; box-shadow: var(--shadow);
    }}
    .subbar p {{ margin: 0; color: var(--foreground); font-size: .9rem; }}
    .subbar .shortcut {{ color: var(--muted); font-size: .82rem; }}
    .stats {{ margin-top: 12px; display: grid; gap: 10px; grid-template-columns: repeat(3, minmax(0,1fr)); }}
    .stats article {{ border: 1px solid var(--line); border-radius: 14px; padding: 12px; background: rgba(255,255,255,.8); box-shadow: var(--shadow); }}
    .stats span {{ color: var(--muted); display: block; font-size: .86rem; }}
    .stats strong {{ display: block; margin-top: 4px; font-size: 1.7rem; }}
    .stats .bar-wrap {{ margin-top: 8px; background: var(--hover-color); border-radius: 999px; height: 8px; overflow: hidden; border: 1px solid var(--border); }}
    .stats .bar {{ height: 100%; background: linear-gradient(90deg, var(--primary), var(--secondary)); width: {run_ratio}%; }}
    .filters {{ margin-top: 12px; display: grid; gap: 10px; grid-template-columns: 1.8fr 1fr 1fr auto; align-items: center; }}
    .filters input, .filters select {{
      border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; font-size: .95rem; background: var(--white); min-height: 42px;
    }}
    .toggle {{ display: inline-flex; align-items: center; gap: 8px; color: var(--foreground); font-size: .9rem; white-space: nowrap; }}
    .toggle input {{ width: 16px; height: 16px; }}
    .notice {{ margin-top: 12px; border-radius: 10px; border: 1px solid; padding: 10px 12px; }}
    .notice.success {{ color: var(--dark-green); background: rgba(16, 185, 129, 0.1); border-color: rgba(16, 185, 129, 0.35); }}
    .notice.error {{ color: var(--error); background: #fef2f2; border-color: #fca5a5; }}
    .table-wrap {{ margin-top: 12px; border: 1px solid var(--line); border-radius: 16px; overflow: auto; background: rgba(255,255,255,.88); box-shadow: var(--shadow); }}
    table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ border-bottom: 1px solid var(--line-soft); text-align: left; padding: 12px; vertical-align: middle; }}
    th {{ background: var(--hover-color); position: sticky; top: 0; }}
    th button {{ all: unset; cursor: pointer; font-weight: 700; }}
    th button::after {{ content: "  <>"; color: #94a3b8; font-weight: 400; font-size: .82em; }}
    tbody tr:nth-child(odd) {{ background: rgba(255, 255, 255, .58); }}
    tbody tr:hover {{ background: var(--hover-color); }}
    .mono {{ font-family: Consolas, "Liberation Mono", Menlo, monospace; font-size: .88rem; }}
    .pill {{ display: inline-flex; border-radius: 999px; padding: 4px 10px; font-size: .78rem; font-weight: 700; }}
    .pill.running {{ background: rgba(16, 185, 129, 0.12); color: var(--dark-green); }}
    .pill.stopped {{ background: rgba(185, 28, 28, 0.12); color: var(--error); }}
    .actions-cell {{ display: inline-flex; gap: 6px; align-items: center; justify-content: center; flex-wrap: wrap; }}
    .actions-cell form {{ margin: 0; }}
    .start-form {{ display: inline-flex; align-items: center; gap: 6px; flex-wrap: wrap; }}
    .port-inline-editor {{ display: inline-flex; align-items: center; gap: 6px; }}
    .port-chip {{
      border: 1px solid var(--border);
      background: var(--white);
      color: var(--muted);
      border-radius: 999px;
      padding: 5px 10px;
      font-size: .76rem;
      line-height: 1;
    }}
    .port-edit-btn {{
      width: 32px;
      height: 32px;
      min-width: 32px;
      padding: 0;
      border-radius: 8px;
      border: 1px solid var(--border);
      background: var(--white);
      color: var(--primary);
      display: inline-flex;
      align-items: center;
      justify-content: center;
    }}
    .port-edit-btn svg {{ width: 16px; height: 16px; fill: currentColor; }}
    .port-edit-btn:hover {{ background: rgba(59, 130, 246, 0.08); }}
    .copy-btn {{ padding: 7px 10px; font-size: .8rem; border: 1px solid var(--border); background: var(--white); color: var(--foreground); }}
    .readme-btn {{
      padding: 7px 10px;
      font-size: .8rem;
      border: 1px solid rgba(15, 23, 42, 0.1);
      background: rgba(15, 23, 42, 0.04);
      color: var(--foreground);
    }}
    .readme-btn:hover {{ background: rgba(15, 23, 42, 0.08); }}
    .open-btn {{
      padding: 7px 10px; font-size: .8rem; border: 1px solid rgba(59, 130, 246, 0.25); background: rgba(59, 130, 246, 0.08); color: var(--primary);
      border-radius: 10px; text-decoration: none; font-weight: 600;
    }}
    .open-btn:hover {{ background: rgba(59, 130, 246, 0.14); }}
    .state-btn {{ padding: 7px 10px; font-size: .8rem; color: #fff; }}
    .state-btn.running {{ background: var(--danger); }}
    .state-btn.stopped {{ background: var(--ok); }}
    .url-link {{ color: var(--primary); text-decoration: none; display: inline-block; max-width: 100%; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }}
    .url-link:hover {{ text-decoration: underline; }}
    .url-text {{ color: var(--muted); }}
    .openapi-link {{ margin-left: 8px; color: var(--secondary); }}
    .empty-state {{
      display: none; padding: 16px; text-align: center; color: var(--muted); background: var(--white); border-top: 1px solid var(--line-soft);
    }}
    .empty-state.show {{ display: block; }}
    .port-modal-backdrop[hidden] {{ display: none; }}
    .port-modal-backdrop {{
      position: fixed;
      inset: 0;
      z-index: 10020;
      background: rgba(15, 23, 42, 0.45);
      display: grid;
      place-items: center;
      padding: 12px;
    }}
    .port-modal {{
      width: min(360px, 100%);
      border-radius: 14px;
      border: 1px solid var(--border);
      background: var(--white);
      box-shadow: 0 18px 36px rgba(15, 23, 42, 0.22);
      padding: 16px;
    }}
    .port-modal h3 {{ margin: 0 0 6px; font-size: 1rem; }}
    .port-modal p {{ margin: 0 0 12px; color: var(--muted); font-size: .88rem; }}
    .port-modal input {{
      width: 100%;
      min-height: 40px;
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 8px 10px;
      font-size: .95rem;
      background: var(--white);
      color: var(--foreground);
    }}
    .port-modal input:focus {{
      outline: 2px solid rgba(59, 130, 246, 0.25);
      outline-offset: 1px;
    }}
    .port-modal-actions {{
      margin-top: 12px;
      display: flex;
      justify-content: flex-end;
      gap: 8px;
    }}
    .readme-modal-backdrop[hidden] {{ display: none; }}
    .readme-modal-backdrop {{
      position: fixed;
      inset: 0;
      z-index: 10010;
      background: rgba(15, 23, 42, 0.52);
      display: grid;
      place-items: center;
      padding: 12px;
    }}
    .readme-modal {{
      width: min(960px, 100%);
      max-height: min(88vh, 920px);
      overflow: hidden;
      border-radius: 16px;
      border: 1px solid var(--border);
      background: var(--white);
      box-shadow: 0 24px 48px rgba(15, 23, 42, 0.24);
      display: grid;
      grid-template-rows: auto 1fr;
    }}
    .readme-modal-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 12px;
      padding: 14px 16px;
      border-bottom: 1px solid var(--line-soft);
    }}
    .readme-modal-header h3 {{ margin: 0; font-size: 1rem; }}
    .readme-close {{
      background: var(--white);
      border: 1px solid var(--border);
      color: var(--foreground);
      min-width: 40px;
    }}
    .readme-content {{
      margin: 0;
      padding: 16px;
      overflow: auto;
      background: #f8fafc;
      color: var(--foreground);
      white-space: pre-wrap;
      word-break: break-word;
      line-height: 1.5;
      font-size: .92rem;
    }}
    .modal-cancel {{
      background: var(--white);
      border: 1px solid var(--border);
      color: var(--foreground);
    }}
    .modal-save {{
      background: var(--primary);
      color: var(--white);
    }}
    @media (max-width: 1080px) {{
      .filters {{ grid-template-columns: 1fr 1fr; }}
    }}
    @media (max-width: 840px) {{
      .stats {{ grid-template-columns: 1fr; }}
      .filters {{ grid-template-columns: 1fr; }}
      .hero-actions {{ width: 100%; }}
      .hero-actions form {{ flex: 1; }}
      .hero-actions button {{ width: 100%; }}
      .subbar {{ align-items: flex-start; }}
      .actions-cell {{ flex-wrap: wrap; }}
      .port-inline-editor {{ width: 100%; justify-content: flex-start; }}
    }}
  </style>
</head>
<body>
  <div class="page">
    <header class="hero">
      <div class="brand">
        {logo_tag}
        <div>
          <p class="eyebrow">ApyGuard Control Center</p>
          <h1>Benchmark Operations Dashboard</h1>
          <p class="meta">LAN: {html.escape(get_host_ip())} | Updated: {generated_at}</p>
        </div>
      </div>
      <div class="hero-actions">
        <form method="get" action="/">
          <button class="refresh" type="submit">Refresh</button>
        </form>
        <form method="post" action="/actions/start-all">
          <button class="start-all" type="submit">Start All Stopped</button>
        </form>
        <form method="post" action="/actions/stop-all-running">
          <button class="stop-all" type="submit">Stop All Running</button>
        </form>
      </div>
    </header>

    <section class="subbar">
      <p><strong id="visibleCount">{total}</strong> of <strong>{total}</strong> benchmarks visible</p>
      <p class="shortcut">Shortcuts: <strong>/</strong> focus search, <strong>R</strong> refresh</p>
    </section>

    <section class="stats">
      <article>
        <span>Total</span>
        <strong>{total}</strong>
        <div class="bar-wrap"><div class="bar"></div></div>
      </article>
      <article><span>Running</span><strong>{running}</strong></article>
      <article><span>Stopped</span><strong>{stopped}</strong></article>
    </section>

    <section class="filters">
      <input id="searchBox" type="text" placeholder="Search by ID, name, or URL..." />
      <select id="statusFilter" aria-label="Status filter">
        <option value="all">All statuses</option>
        <option value="running">Running only</option>
        <option value="stopped">Stopped only</option>
      </select>
      <select id="sortBy" aria-label="Sort by">
        <option value="id">Sort: ID</option>
        <option value="name">Sort: Name</option>
        <option value="port">Sort: Port</option>
        <option value="status">Sort: Status</option>
      </select>
      <label class="toggle" for="autoRefresh">
        <input id="autoRefresh" type="checkbox" />
        Auto refresh (15s)
      </label>
    </section>

    {notice_html}

    <section class="table-wrap">
      <table>
        <thead>
          <tr>
            <th><button type="button" data-sort="id">ID</button></th>
            <th><button type="button" data-sort="name">Name</button></th>
            <th><button type="button" data-sort="port">Port</button></th>
            <th><button type="button" data-sort="status">Status</button></th>
            <th>URL</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody id="benchTable">
          {''.join(row_html)}
        </tbody>
      </table>
      <div id="emptyState" class="empty-state">No benchmarks match current filters.</div>
    </section>
  </div>

  <div id="portModal" class="port-modal-backdrop" hidden>
    <div class="port-modal" role="dialog" aria-modal="true" aria-labelledby="portModalTitle">
      <h3 id="portModalTitle">Edit Port</h3>
      <p>Choose a host port between 1 and 65535.</p>
      <form id="portModalForm">
        <input id="portModalInput" class="mono" type="number" min="1" max="65535" required />
        <div class="port-modal-actions">
          <button id="portModalCancel" class="modal-cancel" type="button">Cancel</button>
          <button class="modal-save" type="submit">Save</button>
        </div>
      </form>
    </div>
  </div>

  <div id="readmeModal" class="readme-modal-backdrop" hidden>
    <div class="readme-modal" role="dialog" aria-modal="true" aria-labelledby="readmeModalTitle">
      <div class="readme-modal-header">
        <h3 id="readmeModalTitle">Benchmark README</h3>
        <button id="readmeClose" class="readme-close" type="button" aria-label="Close README">Close</button>
      </div>
      <pre id="readmeContent" class="readme-content">Loading README...</pre>
    </div>
  </div>

  <script>
    (function () {{
      const searchInput = document.getElementById("searchBox");
      const filterSelect = document.getElementById("statusFilter");
      const sortSelect = document.getElementById("sortBy");
      const autoRefresh = document.getElementById("autoRefresh");
      const visibleCount = document.getElementById("visibleCount");
      const emptyState = document.getElementById("emptyState");
      const tableBody = document.getElementById("benchTable");
      const portModal = document.getElementById("portModal");
      const portModalTitle = document.getElementById("portModalTitle");
      const portModalInput = document.getElementById("portModalInput");
      const portModalForm = document.getElementById("portModalForm");
      const portModalCancel = document.getElementById("portModalCancel");
      const readmeModal = document.getElementById("readmeModal");
      const readmeModalTitle = document.getElementById("readmeModalTitle");
      const readmeContent = document.getElementById("readmeContent");
      const readmeClose = document.getElementById("readmeClose");
      const rows = Array.from(document.querySelectorAll("#benchTable tr"));
      let sortDirection = "asc";
      let refreshTimer = null;
      let activePortTrigger = null;
      let readmeRequest = null;

      function applyFilters() {{
        const term = (searchInput.value || "").toLowerCase().trim();
        const status = filterSelect.value;
        const sortBy = sortSelect.value;

        const visibleRows = rows.filter((row) => {{
          const rowText = row.textContent.toLowerCase();
          const isRunning = row.getAttribute("data-running") === "true";
          const statusMatch = status === "all" || (status === "running" && isRunning) || (status === "stopped" && !isRunning);
          const textMatch = !term || rowText.includes(term);
          return statusMatch && textMatch;
        }});

        const sorted = visibleRows.sort((a, b) => {{
          const attrMap = {{
            id: "data-id",
            name: "data-name",
            port: "data-port",
            status: "data-status"
          }};
          const attr = attrMap[sortBy] || "data-id";
          const av = a.getAttribute(attr) || "";
          const bv = b.getAttribute(attr) || "";
          const aNum = Number(av);
          const bNum = Number(bv);
          let cmp = 0;

          if (!Number.isNaN(aNum) && !Number.isNaN(bNum) && attr !== "data-name" && attr !== "data-id") {{
            cmp = aNum - bNum;
          }} else {{
            cmp = av.localeCompare(bv);
          }}
          return sortDirection === "asc" ? cmp : -cmp;
        }});

        rows.forEach((row) => (row.style.display = "none"));
        sorted.forEach((row) => {{
          row.style.display = "";
          tableBody.appendChild(row);
        }});

        visibleCount.textContent = String(sorted.length);
        emptyState.classList.toggle("show", sorted.length === 0);
      }}

      searchInput.addEventListener("input", applyFilters);
      filterSelect.addEventListener("change", applyFilters);
      sortSelect.addEventListener("change", applyFilters);

      document.querySelectorAll("th button[data-sort]").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          const key = btn.getAttribute("data-sort");
          if (sortSelect.value === key) {{
            sortDirection = sortDirection === "asc" ? "desc" : "asc";
          }} else {{
            sortSelect.value = key;
            sortDirection = "asc";
          }}
          applyFilters();
        }});
      }});

      function setAutoRefresh(enabled) {{
        if (refreshTimer) {{
          window.clearInterval(refreshTimer);
          refreshTimer = null;
        }}
        if (enabled) {{
          refreshTimer = window.setInterval(() => {{
            window.location.href = "/";
          }}, 15000);
        }}
      }}

      autoRefresh.addEventListener("change", () => setAutoRefresh(autoRefresh.checked));

      document.querySelectorAll(".copy-btn").forEach((btn) => {{
        btn.addEventListener("click", async () => {{
          const url = btn.getAttribute("data-url");
          try {{
            await navigator.clipboard.writeText(url);
            btn.textContent = "Copied";
            setTimeout(() => (btn.textContent = "Copy URL"), 900);
          }} catch (_err) {{
            alert("Clipboard permission denied. URL: " + url);
          }}
        }});
      }});

      function closeReadmeModal() {{
        if (readmeRequest) {{
          readmeRequest.abort();
          readmeRequest = null;
        }}
        readmeModal.hidden = true;
        readmeContent.textContent = "";
        document.body.style.overflow = "";
      }}

      async function openReadmeModal(button) {{
        const benchmarkId = button.getAttribute("data-readme-id") || "";
        const benchmarkName = button.getAttribute("data-readme-name") || benchmarkId;
        readmeModalTitle.textContent = "README - " + benchmarkName;
        readmeContent.textContent = "Loading README...";
        readmeModal.hidden = false;
        document.body.style.overflow = "hidden";

        if (readmeRequest) {{
          readmeRequest.abort();
        }}

        readmeRequest = new AbortController();

        try {{
          const response = await fetch("/benchmarks/" + encodeURIComponent(benchmarkId) + "/readme", {{
            signal: readmeRequest.signal
          }});
          if (!response.ok) {{
            throw new Error("Failed to load README (" + String(response.status) + ")");
          }}
          readmeContent.textContent = await response.text();
        }} catch (error) {{
          if (error && error.name === "AbortError") {{
            return;
          }}
          readmeContent.textContent = error instanceof Error ? error.message : "Failed to load README.";
        }} finally {{
          readmeRequest = null;
        }}
      }}

      document.querySelectorAll(".readme-btn").forEach((btn) => {{
        btn.addEventListener("click", () => {{
          openReadmeModal(btn);
        }});
      }});

      function closePortModal() {{
        portModal.hidden = true;
        document.body.style.overflow = "";
        activePortTrigger = null;
      }}

      function openPortModal(trigger) {{
        activePortTrigger = trigger;
        const benchmarkName = trigger.getAttribute("data-benchmark-name") || "benchmark";
        const currentPort = trigger.getAttribute("data-current-port") || "";
        portModalTitle.textContent = "Edit Port - " + benchmarkName;
        portModalInput.value = currentPort;
        portModal.hidden = false;
        document.body.style.overflow = "hidden";
        window.setTimeout(() => {{
          portModalInput.focus();
          portModalInput.select();
        }}, 0);
      }}

      document.querySelectorAll("[data-edit-port]").forEach((btn) => {{
        btn.addEventListener("click", () => openPortModal(btn));
      }});

      portModalCancel.addEventListener("click", closePortModal);
      readmeClose.addEventListener("click", closeReadmeModal);
      portModal.addEventListener("click", (event) => {{
        if (event.target === portModal) {{
          closePortModal();
        }}
      }});
      readmeModal.addEventListener("click", (event) => {{
        if (event.target === readmeModal) {{
          closeReadmeModal();
        }}
      }});

      portModalForm.addEventListener("submit", (event) => {{
        event.preventDefault();
        if (!activePortTrigger) {{
          closePortModal();
          return;
        }}

        const rawPort = (portModalInput.value || "").trim();
        const parsedPort = Number(rawPort);
        if (!rawPort || Number.isNaN(parsedPort) || parsedPort < 1 || parsedPort > 65535) {{
          alert("Port must be between 1 and 65535.");
          return;
        }}

        const benchmarkId = activePortTrigger.getAttribute("data-benchmark-id") || "";
        const startForm = document.querySelector(
          'form[data-start-form][data-benchmark-id="' + benchmarkId + '"]'
        );
        if (startForm) {{
          const hiddenPortInput = startForm.querySelector("[data-port-hidden]");
          if (hiddenPortInput) {{
            hiddenPortInput.value = String(parsedPort);
          }}
        }}

        const portEditor = document.querySelector(
          '.port-inline-editor[data-benchmark-id="' + benchmarkId + '"]'
        );
        if (portEditor) {{
          const chip = portEditor.querySelector("[data-port-chip]");
          if (chip) {{
            chip.textContent = "Port " + String(parsedPort);
          }}
        }}

        activePortTrigger.setAttribute("data-current-port", String(parsedPort));
        const row = activePortTrigger.closest("tr");
        if (row) {{
          row.setAttribute("data-port", String(parsedPort));

          const currentUrl = row.getAttribute("data-url") || "";
          let updatedUrl = currentUrl;
          if (/:\\d+$/.test(currentUrl)) {{
            updatedUrl = currentUrl.replace(/:\\d+$/, ":" + String(parsedPort));
          }} else if (currentUrl) {{
            updatedUrl = currentUrl + ":" + String(parsedPort);
          }}
          if (updatedUrl) {{
            row.setAttribute("data-url", updatedUrl);
            const urlText = row.querySelector(".url-text");
            if (urlText) {{
              urlText.textContent = updatedUrl;
            }}

            const copyBtn = row.querySelector(".copy-btn");
            if (copyBtn) {{
              copyBtn.setAttribute("data-url", updatedUrl);
            }}

            const openApiUrl = updatedUrl.replace(/\\/$/, "") + "/openapi.json";
            const openBtn = row.querySelector(".open-btn");
            if (openBtn) {{
              openBtn.setAttribute("href", openApiUrl);
            }}

            const openapiLink = row.querySelector(".openapi-link");
            if (openapiLink) {{
              openapiLink.setAttribute("href", openApiUrl);
            }}
          }}
        }}

        closePortModal();
      }});

      document.addEventListener("keydown", (event) => {{
        if (event.key === "Escape") {{
          if (!portModal.hidden) {{
            closePortModal();
            return;
          }}
          if (!readmeModal.hidden) {{
            closeReadmeModal();
            return;
          }}
          return;
        }}
        if (event.key === "/" && document.activeElement !== searchInput) {{
          event.preventDefault();
          searchInput.focus();
        }}
        if ((event.key === "r" || event.key === "R") && document.activeElement.tagName !== "INPUT") {{
          window.location.href = "/";
        }}
      }});

      applyFilters();
    }})();
  </script>
</body>
</html>
"""

    def _read_form_data(self) -> dict[str, list[str]]:
        content_length = int(self.headers.get("Content-Length", "0"))
        if content_length <= 0:
            return {}
        raw_payload = self.rfile.read(content_length).decode("utf-8")
        return parse_qs(raw_payload)

    def do_GET(self) -> None:
        split = urlsplit(unquote(self.path))
        path = split.path
        query = parse_qs(split.query)

        asset_match = re.match(r"^/assets/([^/]+)$", path)
        if asset_match:
            file_path = safe_asset_path(asset_match.group(1))
            if file_path:
                self._send_file(HTTPStatus.OK, file_path)
                return
            self._send_html(HTTPStatus.NOT_FOUND, "<h1>Asset not found</h1>")
            return

        readme_match = re.match(r"^/benchmarks/(APY-\d{3}-\d{2})/readme$", path)
        if readme_match:
            readme_path = safe_benchmark_readme_path(readme_match.group(1))
            if readme_path:
                self._send_text(HTTPStatus.OK, readme_path.read_text(encoding="utf-8"), "text/plain")
                return
            self._send_text(HTTPStatus.NOT_FOUND, "README not found.", "text/plain")
            return

        if path != "/":
            self._send_html(HTTPStatus.NOT_FOUND, "<h1>Not found</h1>")
            return

        msg = query.get("msg", [""])[0]
        kind = query.get("kind", ["success"])[0]
        self._send_html(HTTPStatus.OK, self._dashboard_html(msg=msg, kind=kind))

    def do_POST(self) -> None:
        path = urlsplit(unquote(self.path)).path
        form_data = self._read_form_data()
        benchmarks = {b.benchmark_id: b for b in discover_benchmarks()}

        if path == "/actions/start-all":
            changed = 0
            for benchmark in benchmarks.values():
                if not benchmark_running(benchmark):
                    ok, _ = start_benchmark(benchmark)
                    if ok:
                        changed += 1
            self._redirect(f"Started {changed} benchmark(s).")
            return

        if path == "/actions/stop-all-running":
            changed = 0
            for benchmark in benchmarks.values():
                if benchmark_running(benchmark):
                    ok, _ = stop_benchmark(benchmark)
                    if ok:
                        changed += 1
            self._redirect(f"Stopped {changed} benchmark(s).")
            return

        match = re.match(r"^/actions/(APY-\d{3}-\d{2})/(start|stop)$", path)
        if not match:
            self._redirect("Unknown action.", kind="error")
            return

        benchmark_id, action = match.groups()
        benchmark = benchmarks.get(benchmark_id)
        if not benchmark:
            self._redirect(f"Unknown benchmark: {benchmark_id}", kind="error")
            return

        port_override = None
        if action == "start":
            port_raw = form_data.get("port", [""])[0].strip()
            if port_raw:
                if not port_raw.isdigit():
                    self._redirect("Port must be a number.", kind="error")
                    return
                port_override = int(port_raw)
                if not (1 <= port_override <= 65535):
                    self._redirect("Port must be between 1 and 65535.", kind="error")
                    return

        ok, message = (
            start_benchmark(benchmark, port_override=port_override)
            if action == "start"
            else stop_benchmark(benchmark)
        )
        if ok:
            self._redirect(message)
            return
        self._redirect(message, kind="error")


def main() -> None:
    host = "0.0.0.0"
    port = 8090
    server = ThreadingHTTPServer((host, port), DashboardHandler)
    print(f"Dashboard listening: http://127.0.0.1:{port}")
    print(f"LAN access: http://{get_host_ip()}:{port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
