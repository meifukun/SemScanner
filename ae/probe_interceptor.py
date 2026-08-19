#!/usr/bin/env python3
"""Isolated probe: does the selenium-wire request interceptor abort the XSS beacon XHR?

Replicates attack_executor._create_new_driver() chrome options + interceptor, then fires
an XHR to the beacon listener (127.0.0.1:9091) from a real page, with and without the
interceptor. Checks whether the listener actually receives the callback token.
"""
import threading, time, urllib.parse, http.server, socketserver, os, sys, json

CAPTURE_FILE = "/tmp/semscanner-home/probe_captured.txt"
os.makedirs(os.path.dirname(CAPTURE_FILE), exist_ok=True)
with open(CAPTURE_FILE, "w") as _f:
    _f.write("")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        qs = urllib.parse.urlparse(self.path).query
        data = urllib.parse.parse_qs(qs).get("data", [""])[0]
        if data:
            try:
                with open(CAPTURE_FILE, "a") as f:
                    f.write(data + "\n")
            except Exception as e:
                sys.stderr.write(f"[listener write err] {e}\n")
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        try:
            self.wfile.write(b"ok")
        except Exception:
            pass
    def log_message(self, *a): pass

def start_listener(port=9091):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

def make_driver(interceptor_mode, target_domain="web"):
    """interceptor_mode: 'buggy' | 'fixed' | 'none'"""
    from seleniumwire import webdriver
    from utils.chrome_driver import configure_chrome_options, make_chrome_service
    options = webdriver.ChromeOptions()
    for a in ["--headless=new","--no-sandbox","--disable-dev-shm-usage",
              "--disable-gpu","--disable-web-security",
              "--allow-running-insecure-content","--disable-xss-auditor"]:
        options.add_argument(a)
    options.page_load_strategy = "eager"
    options = configure_chrome_options(options)
    driver = webdriver.Chrome(service=make_chrome_service(), options=options)
    driver.set_page_load_timeout(60)
    driver.set_script_timeout(60)
    if interceptor_mode == "buggy":
        def interceptor(request):
            if target_domain not in request.url:
                request.abort()
        driver.request_interceptor = interceptor
    elif interceptor_mode == "fixed":
        def interceptor(request):
            if '127.0.0.1' in request.url or 'localhost' in request.url:
                return
            if target_domain not in request.url:
                request.abort()
        driver.request_interceptor = interceptor
    return driver

def fire_beacon(driver, token):
    # Replicate js/xss_xhr.js: plain XHR GET to beacon url
    js = (
        "var xhr=new XMLHttpRequest();"
        "xhr.open('GET','http://127.0.0.1:9091/?data=%s',true);"
        "try{xhr.send();}catch(e){}"
    ) % token
    try:
        driver.execute_script(js)
    except Exception as e:
        print(f"  [fire] execute_script error: {e}")

def seen(token):
    try:
        return token in open(CAPTURE_FILE).read()
    except: return False

def main():
    srv = start_listener()
    time.sleep(0.5)
    # sanity: listener reachable from python (not via browser)
    import urllib.request
    try:
        urllib.request.urlopen("http://127.0.0.1:9091/?data=PYTHON_SANITY", timeout=3).read()
    except Exception as e:
        print("LISTENER NOT REACHABLE FROM PYTHON:", e); sys.exit(2)
    print("PYTHON_SANITY seen:", seen("PYTHON_SANITY"))

    page = "http://web/login.php"
    results = {}
    for label, mode in [("BUGGY_INTERCEPTOR", "buggy"), ("FIXED_INTERCEPTOR", "fixed"), ("NO_INTERCEPTOR", "none")]:
        token = "PROBE_" + label
        print(f"\n=== {label} (mode={mode}) ===")
        d = make_driver(mode)
        try:
            d.get(page)
            print(f"  navigated to {d.current_url}")
            fire_beacon(d, token)
            time.sleep(3)
            ok = seen(token)
            results[label] = ok
            print(f"  listener received {token}: {ok}")
        except Exception as e:
            print(f"  ERROR: {e}")
            results[label] = f"ERR:{e}"
        finally:
            try: d.quit()
            except: pass
    srv.shutdown()
    print("\n==== PROBE RESULT ====")
    print(json.dumps(results, indent=2))
    if results.get("BUGGY_INTERCEPTOR") is False and results.get("FIXED_INTERCEPTOR") is True:
        print("\nCONFIRMED: fixed interceptor lets the beacon through (buggy one blocked it).")
    else:
        print("\nUnexpected — investigate.")

if __name__ == "__main__":
    main()
