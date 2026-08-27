#!/usr/bin/env python3
"""Local demo host for The Hunt Engine.

Serves static files from this folder, HTTP 302 chains, pastebin-style
probe targets, soft-404 misses, and a local pin stub.

Usage:
  python server.py
  # then open http://127.0.0.1:8765/
  # practice hunt: http://127.0.0.1:8765/practice/
"""

from __future__ import annotations

import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent
HOST = "127.0.0.1"
PORT = 8765

REDIRECTS = {
    "/r/start": "/r/mid",
    "/r/mid": "/r/end",
    "/r/end": "/final.html",
    "/practice/r/alpha": "/practice/r/beta",
    "/practice/r/beta": "/practice/r/gamma",
    "/practice/r/gamma": "/practice/nest.html",
}

# Tokens inventively named for Neon Rook — not live-contest IDs.
PASTE_BODIES = {
    "nr00k7px": """NEON ROOK // DROP 2
====================
You hit a real paste on the demo hunt base.

geohash-lookalike (fiction, not map data):
  9v6kph00

Open on this origin:
  /practice/9v6kph00.html

Wrong ids under /raw/ /p/ /paste/ return soft-404 bodies (HTTP 200).
""",
    "neonrook": """NEON ROOK // SIDE PATH
Optional slug hit. Trailhead: /practice/
""",
}

PIN_IDS = {
    "8472910563840123456": "/practice/pin-stub.html",
}

PROBE_PREFIXES = ("/raw/", "/p/", "/paste/", "/a/", "/file/")
PRACTICE_PROBE_ROOTS = ("", "/practice")

SOFT_404_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>Not Found (#404)</title>
  <link rel="stylesheet" href="/styles.css" />
</head>
<body>
  <main class="hero">
    <h1>Not Found (#404)</h1>
    <p class="lede">This page has been removed or the id does not exist.</p>
    <p>error-404 · soft-404 body for Hunt Engine probe practice.</p>
    <p><a class="btn" href="/practice/">Neon Rook trailhead</a></p>
  </main>
</body>
</html>
"""

# Paths that must remain static / reserved (never soft-404 as bare /{id}).
RESERVED_ROOT = {
    "",
    "index.html",
    "styles.css",
    "server.py",
    "final.html",
    "meta-hop1.html",
    "meta-hop2.html",
    "meta-final.html",
    "frame-clue.html",
    "practice",
    "r",
    "raw",
    "p",
    "paste",
    "a",
    "file",
    "pin",
}


class HuntDemoHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        path = unquote(self.path.split("?", 1)[0])

        if path in REDIRECTS:
            target = REDIRECTS[path]
            self.send_response(302)
            self.send_header("Location", target)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.log_message("302 %s -> %s", path, target)
            return

        if path in ("", "/"):
            self.path = "/index.html"
            return super().do_GET()

        if path in ("/practice", "/practice/"):
            self.path = "/practice/index.html"
            return super().do_GET()

        pin = self._pin_id(path)
        if pin is not None:
            return self._serve_pin(pin)

        paste_id = self._paste_id(path)
        if paste_id is not None:
            return self._serve_paste(paste_id, path)

        practice_page = self._practice_page(path)
        if practice_page == "soft404":
            return self._send_soft_404()
        if practice_page is not None:
            self.path = practice_page
            return super().do_GET()

        # Bare /{id} hunt-base probes: hit known tokens, soft-404 unknown-looking ids.
        bare = path.lstrip("/")
        if bare and "/" not in bare and "." not in bare and bare.lower() not in RESERVED_ROOT:
            key = bare.lower() if bare.lower() in PASTE_BODIES else bare
            if key in PASTE_BODIES or bare in PASTE_BODIES:
                return self._serve_paste(bare if bare in PASTE_BODIES else key, path)
            if self._looks_like_probe_id(bare):
                return self._send_soft_404()

        return super().do_GET()

    def _looks_like_probe_id(self, value: str) -> bool:
        if len(value) < 4 or len(value) > 64:
            return False
        return all(c.isalnum() or c in "_-" for c in value)

    def _practice_page(self, path: str) -> str | None:
        """Map /practice/{id} → /practice/{id}.html when present; soft404 for probe-shaped misses."""
        if not path.startswith("/practice/"):
            return None
        rest = path[len("/practice/") :].strip("/")
        if not rest or "/" in rest or "." in rest:
            return None
        if not self._looks_like_probe_id(rest):
            return None
        candidate = ROOT / "practice" / (rest + ".html")
        if candidate.is_file():
            return "/practice/" + rest + ".html"
        return "soft404"

    def _paste_id(self, path: str) -> str | None:
        for root in PRACTICE_PROBE_ROOTS:
            for prefix in PROBE_PREFIXES:
                full = root + prefix
                if path.startswith(full):
                    rest = path[len(full) :].strip("/")
                    if rest and "/" not in rest:
                        return rest
        return None

    def _pin_id(self, path: str) -> str | None:
        if not path.startswith("/pin/"):
            return None
        rest = path[len("/pin/") :].strip("/")
        if rest.endswith("/"):
            rest = rest[:-1]
        if rest and "/" not in rest:
            return rest
        return None

    def _serve_paste(self, paste_id: str, request_path: str):
        body = PASTE_BODIES.get(paste_id) or PASTE_BODIES.get(paste_id.lower())
        if body is None:
            self.log_message("soft-404 paste %s (%s)", paste_id, request_path)
            return self._send_soft_404()
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        self.log_message("200 paste hit %s", paste_id)

    def _serve_pin(self, pin_id: str):
        target = PIN_IDS.get(pin_id)
        if not target:
            self.log_message("soft-404 pin %s", pin_id)
            return self._send_soft_404()
        # Serve stub HTML at /pin/{id} so the numeric id remains in the URL.
        stub_path = ROOT.joinpath(*target.strip("/").split("/"))
        if not stub_path.is_file():
            return self._send_soft_404()
        data = stub_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)
        self.log_message("200 pin stub %s", pin_id)

    def _send_soft_404(self):
        data = SOFT_404_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt % args))


def main():
    parser = argparse.ArgumentParser(description="Hunt Engine demo server")
    parser.add_argument("--host", default=HOST)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), HuntDemoHandler)
    print("Hunt Engine demo arena")
    print("  Open:           http://%s:%s/" % (args.host, args.port))
    print("  Practice hunt:  http://%s:%s/practice/" % (args.host, args.port))
    print("  HTTP chain:     /r/start -> /r/mid -> /r/end -> /final.html")
    print("  Practice chain: /practice/r/alpha -> ... -> /practice/nest.html")
    print("  Paste hit:      /raw/nr00k7px  (also /practice/raw/…)")
    print("  robots/sitemap: /robots.txt · /sitemap.xml")
    print("  Pin stub:       /pin/8472910563840123456")
    print("  Ctrl+C to stop")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
        server.server_close()


if __name__ == "__main__":
    main()
