import os
import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus
from datetime import datetime
import socket

class SimpleXssHandler(BaseHTTPRequestHandler):
    # Suppress default logging to stderr (can be enabled as needed)
    def log_message(self, format, *args):
        return

    def _set_common_headers(self):
        # Minimal response headers: allow CORS, text utf-8
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
    
    def do_OPTIONS(self):
        # respond to preflight if any
        self.send_response(200)
        self._set_common_headers()
        self.end_headers()

    def do_GET(self):
        try:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            # Only process requests containing a "data" parameter; if no "data" parameter, skip
            raw_vals = qs.get("data", [])
            if raw_vals:
                data_raw = raw_vals[0]
            else:
                # If no data parameter, return directly without logging anything
                self.send_response(400)  # Optional: Return an error response
                self._set_common_headers()
                self.end_headers()
                self.wfile.write(b"ERR: Missing 'data' parameter")
                return

            # decode + normalize
            try:
                data_decoded = unquote_plus(data_raw)
            except Exception:
                data_decoded = data_raw

            # Get the log file path and the set of recorded payloads
            logfile = getattr(self.server, "xss_logfile", None)
            if logfile:
                # Storage for recorded data
                if not hasattr(self.server, 'logged_data'):
                    self.server.logged_data = set()  # Store recorded payloads

                # Check if data has already been recorded
                if data_decoded in self.server.logged_data:
                    self.send_response(200)
                    self._set_common_headers()
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

                # Add data to the recorded set
                self.server.logged_data.add(data_decoded)

                # Write to log file
                parent = os.path.dirname(logfile)
                if parent:
                    os.makedirs(parent, exist_ok=True)
                with open(logfile, "a", encoding="utf-8") as wf:
                    wf.write(data_decoded + "\n")

            # reply minimal response
            self.send_response(200)
            self._set_common_headers()
            self.end_headers()
            self.wfile.write(b"OK")
        except Exception as e:
            # best-effort error response
            try:
                self.send_response(500)
                self._set_common_headers()
                self.end_headers()
                msg = f"ERR: {e}"
                self.wfile.write(msg.encode("utf-8", errors="replace"))
            except Exception:
                pass


def start_xss_listener(bind_addr: str = "127.0.0.1", port: int = 9091, logfile: str = "./xss_captured.txt", no_print: bool = False):
    """
    Start an HTTPServer (running in a background thread), returns (server, thread).
    The caller is responsible for calling server.shutdown() at the appropriate time.
    """
    server = HTTPServer((bind_addr, port), SimpleXssHandler)
    # store logfile path and no_print flag on server so handler can access it
    server.xss_logfile = logfile
    server.no_print = no_print

    thr = threading.Thread(target=server.serve_forever, daemon=True)
    thr.start()
    return server, thr

def find_free_port():
    """Helper: find a free port (only for user debugging/prompting)"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("", 0))
    addr, port = s.getsockname()
    s.close()
    return port

def main():
    parser = argparse.ArgumentParser(description="Simple XSS callback HTTP listener")
    parser.add_argument("--bind", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=9091, help="Port to listen on (default: 9091)")
    parser.add_argument("--logfile", default="request_captured.txt", help="File to append captured payloads to (default: request_captured.txt)")
    parser.add_argument("--no-print", action="store_true", help="Do not print incoming payloads to stdout")
    args = parser.parse_args()

    try:
        server, thr = start_xss_listener(bind_addr=args.bind, port=args.port, logfile=args.logfile, no_print=args.no_print)
    except OSError as e:
        print(f"[ERROR] failed to start server on {args.bind}:{args.port} -> {e}")
        # optionally suggest a free port
        try:
            free = find_free_port()
            print(f"[TIP] try --port {free}")
        except Exception:
            pass
        return

    try:
        # keep main thread alive while server runs in background thread
        while True:
            thr.join(1.0)
            if not thr.is_alive():
                break
    except KeyboardInterrupt:
        print("\n[XSS LISTENER] shutting down...")
    finally:
        # graceful shutdown
        try:
            server.shutdown()
            server.server_close()
            print("[XSS LISTENER] stopped")
        except Exception as e:
            print(f"[XSS LISTENER] error during shutdown: {e}")

if __name__ == "__main__":
    main()

# curl http://127.0.0.1:9091/?data=nihaoa
# nohup python listen_server.py --logfile http_captured.txt &> listener.log &
# 3553974

