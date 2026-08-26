import http.server
import json
import os


TOKEN = os.environ["DBPILOT_FIXTURE_TOKEN"]
with open(os.environ["DBPILOT_FIXTURE_FILE"], "rb") as fixture_file:
    PAYLOAD = fixture_file.read()
json.loads(PAYLOAD)


class ReadOnlyJMXHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.headers.get("Authorization") != "Bearer " + TOKEN:
            self.send_error(401)
            return
        if self.path == "/health":
            body = b'{"status":"ok"}'
        elif self.path == "/jmx":
            body = PAYLOAD
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format_string, *args):
        print("fixture request: " + format_string % args, flush=True)


http.server.ThreadingHTTPServer(("0.0.0.0", 8000), ReadOnlyJMXHandler).serve_forever()
