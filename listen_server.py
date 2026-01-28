import os
import argparse
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs, unquote_plus
from datetime import datetime
import socket

class SimpleXssHandler(BaseHTTPRequestHandler):
    # 取消默认把日志写到 stderr（可按需打开）
    def log_message(self, format, *args):
        return

    def _set_common_headers(self):
        # 最小响应头：允许跨域，文本utf-8
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
            # 只处理包含 "data" 参数的请求，若无 "data" 参数，则不做处理
            raw_vals = qs.get("data", [])
            if raw_vals:
                data_raw = raw_vals[0]
            else:
                # 如果没有 data 参数，直接返回，不记录任何信息
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

            # 获取日志文件路径和已记录的payload集合
            logfile = getattr(self.server, "xss_logfile", None)
            if logfile:
                # 用于存储已记录的 data
                if not hasattr(self.server, 'logged_data'):
                    self.server.logged_data = set()  # 用来存储已记录的 payload

                # 检查 data 是否已经被记录
                if data_decoded in self.server.logged_data:
                    self.send_response(200)
                    self._set_common_headers()
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

                # 将 data 添加到已记录的集合
                self.server.logged_data.add(data_decoded)

                # 写入日志文件
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
    启动 HTTPServer（在后台线程运行），返回 (server, thread).
    调用者负责在合适时机调用 server.shutdown().
    """
    server = HTTPServer((bind_addr, port), SimpleXssHandler)
    # store logfile path and no_print flag on server so handler can access it
    server.xss_logfile = logfile
    server.no_print = no_print

    thr = threading.Thread(target=server.serve_forever, daemon=True)
    thr.start()
    return server, thr

def find_free_port():
    """辅助：找一个空闲端口（仅用于用户调试/提示）"""
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

