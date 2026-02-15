"""
Exfiltration sink -- dumb HTTP server + host-side log parser.

Build Order: Step 8

The sink itself is a minimal HTTP server that runs inside a container
and logs every request as JSON to stdout. All intelligence (canary
detection) happens host-side via parse_sink_logs().
"""

import json

SINK_PORT = 8666

SINK_SERVER_CODE = f'''
import json, http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def _handle(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="replace") if length else ""
        print(json.dumps({{
            "ts": __import__("datetime").datetime.utcnow().isoformat() + "Z",
            "method": self.command,
            "path": self.path,
            "headers": dict(self.headers),
            "body": body[:10000],
            "src": self.client_address[0],
        }}), flush=True)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle
    def log_message(self, *a): pass

with socketserver.TCPServer(("0.0.0.0", {SINK_PORT}), H) as s:
    s.serve_forever()
'''


def parse_sink_logs(
    log_bytes: bytes,
    canary_values: dict[str, str],
) -> list[dict]:
    """
    Parse sink container logs and perform HOST-SIDE canary detection.

    Args:
        log_bytes: raw stdout from sink container
        canary_values: {env_var_name: canary_value} to search for

    Returns:
        List of capture dicts with contains_canary and matched_canary_keys
        populated by THIS function, not the sink.
    """
    captures: list[dict] = []
    for line in log_bytes.decode(errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue

        # HOST-SIDE canary detection
        # Search body, headers, and path for any canary value
        searchable = (
            record.get("body", "")
            + json.dumps(record.get("headers", {}))
            + record.get("path", "")
        )
        matched: list[str] = []
        for env_key, canary_val in canary_values.items():
            if canary_val in searchable:
                matched.append(env_key)

        record["contains_canary"] = len(matched) > 0
        record["matched_canary_keys"] = matched
        captures.append(record)

    return captures
