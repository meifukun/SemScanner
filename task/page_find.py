# task/page_find.py
# -*- coding: utf-8 -*-
import re, json, os, hashlib, html
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Iterable, Optional, Set
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import time

try:
    from bs4 import BeautifulSoup  # Optional; works without it but falls back to regex
except Exception:
    BeautifulSoup = None

# task/page_find.py
CONFIG = {
    "require_same_path": False,   # Changed to False: different paths also participate in content similarity comparison
    "dom_n_gram": 3,
    "text_hamming_thresh": 1,
    "dom_hamming_thresh": 1,
    "update_text_hamming_thresh": 2,
    "update_dom_hamming_thresh": 6,
    "repr_policy": "shortest",
    "print_singletons": False,
}

# def _strip_fragment(u: str) -> str:
#     """Remove fragment, but keep SPA routes (#/xxx)"""
#     pu = urlparse(u)
#     # If fragment looks like a route path (starts with /), keep it
#     if pu.fragment and pu.fragment.startswith('/'):
#         return u  # Keep as-is
#     return urlunparse((pu.scheme, pu.netloc, pu.path or "/", pu.params, pu.query, ""))

from urllib.parse import urlparse, urlunparse

def _strip_fragment(u: str) -> str:
    """
    Only remove fragment when '#' appears after '?'.
    Otherwise keep the URL completely unchanged.
    """

    # Find positions of '?' and '#' (-1 if not present)
    q = u.find("?")
    h = u.find("#")

    # Case 1: No '?' => keep as-is
    if q == -1:
        return u

    # Case 2: Has '?', but '#' is before '?' => keep as-is
    if h == -1 or h < q:
        return u

    # Case 3: '#' appears after '?' => perform strip fragment
    pu = urlparse(u)
    return urlunparse((pu.scheme, pu.netloc, pu.path or "/", pu.params, pu.query, ""))


def normalize_url(u: str) -> str:
    return _strip_fragment(u)

def _same_path_only(ua: str, ub: str) -> bool:
    pa = re.sub(r"/{2,}", "/", (urlparse(ua).path or "/"))
    pb = re.sub(r"/{2,}", "/", (urlparse(ub).path or "/"))
    return pa == pb

def _url_equiv(ua: str, ub: str) -> bool:
    return ua == ub

# def extract_main_text(html_str: str) -> str:
#     if not html_str:
#         return ""
#     if BeautifulSoup is None:
#         text = re.sub(r"(?is)<(script|style|noscript|template).*?</\1>", " ", html_str)
#         text = re.sub(r"(?is)<[^>]+>", " ", text)
#     else:
#         try:
#             soup = BeautifulSoup(html_str, "lxml")
#         except Exception:
#             soup = BeautifulSoup(html_str, "html.parser")
#         for tag in soup(["script", "style", "noscript", "template"]):
#             tag.decompose()
#         for sel in [
#             "header","footer","nav",".nav",".header",".footer",
#             ".ads",".ad",".recommend",".sidebar",".breadcrumbs",".login",".subscribe"
#         ]:
#             for t in soup.select(sel):
#                 t.decompose()
#         text = soup.get_text(" ", strip=True)

#     text = html.unescape(text)
#     text = re.sub(r"\s+", " ", text).strip()
#     text = re.sub(r"\b\d{1,2}:\d{2}(:\d{2})?\b", " <TIME> ", text)
#     text = re.sub(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b", " <DATE> ", text)
#     return text

def extract_main_text(html_str: str, driver=None) -> str:
    """
    Extract main text content

    Args:
        html_str: HTML source code (for fallback)
        driver: Selenium WebDriver (optional, for getting visible text)

    Returns:
        str: Cleaned text
    """
    # If driver is provided, use JavaScript to get visible text (fast approach)
    if driver:
        try:
            visible_text = driver.execute_script("""
                // Recursively get visible element text
                function getVisibleText(el) {
                    if (!el) return '';
                    
                    // Check if element is visible
                    const style = window.getComputedStyle(el);
                    if (style.display === 'none' || 
                        style.visibility === 'hidden' || 
                        parseFloat(style.opacity) === 0) {
                        return '';
                    }
                    
                    // Exclude script/style/noscript
                    const tagName = el.tagName ? el.tagName.toLowerCase() : '';
                    if (['script', 'style', 'noscript', 'template'].includes(tagName)) {
                        return '';
                    }
                    
                    // Exclude common non-content areas
                    const className = el.className || '';
                    const classStr = typeof className === 'string' ? className : '';
                    if (/header|footer|nav|ads|ad-|sidebar|breadcrumb|login|subscribe/i.test(classStr)) {
                        return '';
                    }
                    
                    // Get text nodes
                    let text = '';
                    for (let node of el.childNodes) {
                        if (node.nodeType === Node.TEXT_NODE) {
                            text += node.textContent + ' ';
                        } else if (node.nodeType === Node.ELEMENT_NODE) {
                            text += getVisibleText(node) + ' ';
                        }
                    }
                    
                    return text;
                }
                
                return getVisibleText(document.body);
            """)
            
            if visible_text and visible_text.strip():
                # Clean text
                text = html.unescape(visible_text)
                text = re.sub(r'\s+', ' ', text).strip()
                text = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\b', ' <TIME> ', text)
                text = re.sub(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b', ' <DATE> ', text)
                return text
            else:
                print("    [Warning: driver returned empty text, falling back to HTML parsing]")
        except Exception as e:
            print(f"    [Warning: driver extraction failed ({e}), falling back to HTML parsing]")
    
    # Fallback: use original HTML parsing method
    if not html_str:
        return ""
    
    if BeautifulSoup is None:
        text = re.sub(r"(?is)<(script|style|noscript|template).*?</\1>", " ", html_str)
        text = re.sub(r"(?is)<[^>]+>", " ", text)
    else:
        try:
            soup = BeautifulSoup(html_str, "lxml")
        except Exception:
            soup = BeautifulSoup(html_str, "html.parser")
        for tag in soup(["script", "style", "noscript", "template"]):
            tag.decompose()
        for sel in [
            "header","footer","nav",".nav",".header",".footer",
            ".ads",".ad",".recommend",".sidebar",".breadcrumbs",".login",".subscribe"
        ]:
            for t in soup.select(sel):
                t.decompose()
        text = soup.get_text(" ", strip=True)

    text = html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    text = re.sub(r"\b\d{1,2}:\d{2}(:\d{2})?\b", " <TIME> ", text)
    text = re.sub(r"\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b", " <DATE> ", text)
    return text

def _hash64(x: str) -> int:
    return int(hashlib.blake2b(x.encode("utf-8"), digest_size=8).hexdigest(), 16)

def shingles(s: str, k: int = 5) -> Iterable[str]:
    s = s.strip()
    if len(s) <= k:
        yield s
    else:
        for i in range(len(s) - k + 1):
            yield s[i:i+k]

def simhash_from_tokens(tokens: Iterable[str], bits: int = 64) -> int:
    v = [0]*bits
    for tok in tokens:
        h = _hash64(tok)
        for i in range(bits):
            v[i] += 1 if (h >> i) & 1 else -1
    fp = 0
    for i in range(bits):
        if v[i] >= 0:
            fp |= (1 << i)
    return fp

def hamming(a: int, b: int) -> int:
    return (a ^ b).bit_count()

def text_simhash(text: str) -> int:
    return simhash_from_tokens(shingles(text, 5))

SELF_CLOSING = {"br","hr","img","input","meta","link"}

# def dom_tag_sequence(html_str: str) -> List[str]:
#     if BeautifulSoup is None:
#         return [m.lower() for m in re.findall(r"<\s*([a-zA-Z0-9]+)", html_str or "")]
#     try:
#         soup = BeautifulSoup(html_str, "lxml")
#     except Exception:
#         soup = BeautifulSoup(html_str, "html.parser")
#     for tag in soup(["script","style","noscript","template"]):
#         tag.decompose()
#     for sel in [
#         "header","footer","nav",".nav",".header",".footer",
#         ".ads",".ad",".recommend",".sidebar",".breadcrumbs",".login",".subscribe"
#     ]:
#         for t in soup.select(sel):
#             t.decompose()
#     seq: List[str] = []
#     def walk(node):
#         if getattr(node, "name", None):
#             name = node.name.lower()
#             seq.append(name)
#             for ch in getattr(node, "children", []):
#                 walk(ch)
#             if name not in SELF_CLOSING:
#                 seq.append(f"/{name}")
#     walk(soup.body or soup)
#     return seq

def dom_tag_sequence(html_str: str, driver=None) -> List[str]:
    """
    Extract DOM tag sequence

    Args:
        html_str: HTML source code (for fallback)
        driver: Selenium WebDriver (optional, for getting visible element DOM structure only)

    Returns:
        List[str]: Tag sequence
    """
    # If driver is provided, use JavaScript to get visible element DOM structure
    if driver:
        try:
            print("    [Using driver to extract visible DOM structure]")
            visible_tags = driver.execute_script("""
                // Recursively traverse visible elements, collect tag sequence
                function getVisibleDOMSequence(el, sequence) {
                    if (!el || !el.tagName) return;
                    
                    // Check if element is visible
                    const style = window.getComputedStyle(el);
                    if (style.display === 'none' || 
                        style.visibility === 'hidden' || 
                        parseFloat(style.opacity) === 0) {
                        return;
                    }
                    
                    const tagName = el.tagName.toLowerCase();
                    
                    // Exclude script/style/noscript
                    if (['script', 'style', 'noscript', 'template'].includes(tagName)) {
                        return;
                    }
                    
                    // Exclude common non-content areas
                    const className = el.className || '';
                    const classStr = typeof className === 'string' ? className : '';
                    if (/header|footer|nav|ads|ad-|sidebar|breadcrumb|login|subscribe/i.test(classStr)) {
                        return;
                    }
                    
                    // Add opening tag
                    sequence.push(tagName);
                    
                    // Traverse child elements
                    for (let child of el.children) {
                        getVisibleDOMSequence(child, sequence);
                    }
                    
                    // Add closing tag (exclude self-closing tags)
                    const selfClosing = ['br', 'hr', 'img', 'input', 'meta', 'link'];
                    if (!selfClosing.includes(tagName)) {
                        sequence.push('/' + tagName);
                    }
                }
                
                const sequence = [];
                getVisibleDOMSequence(document.body, sequence);
                return sequence;
            """)
            
            if visible_tags and len(visible_tags) > 0:
                return visible_tags
            else:
                print("    [Warning: driver returned empty DOM sequence, falling back to HTML parsing]")
        except Exception as e:
            print(f"    [Warning: driver DOM extraction failed ({e}), falling back to HTML parsing]")
    
    # Fallback: use original HTML parsing method
    print("    [Using HTML parsing to extract DOM structure]")
    if BeautifulSoup is None:
        return [m.lower() for m in re.findall(r"<\s*([a-zA-Z0-9]+)", html_str or "")]
    
    try:
        soup = BeautifulSoup(html_str, "lxml")
    except Exception:
        soup = BeautifulSoup(html_str, "html.parser")
    
    for tag in soup(["script","style","noscript","template"]):
        tag.decompose()
    for sel in [
        "header","footer","nav",".nav",".header",".footer",
        ".ads",".ad",".recommend",".sidebar",".breadcrumbs",".login",".subscribe"
    ]:
        for t in soup.select(sel):
            t.decompose()
    
    seq: List[str] = []
    def walk(node):
        if getattr(node, "name", None):
            name = node.name.lower()
            seq.append(name)
            for ch in getattr(node, "children", []):
                walk(ch)
            if name not in SELF_CLOSING:
                seq.append(f"/{name}")
    walk(soup.body or soup)
    return seq

def dom_simhash(html_str: str, n: int = 3, driver=None) -> int:
    seq = dom_tag_sequence(html_str, driver=driver)
    if not seq:
        return 0
    grams = ["|".join(seq)] if len(seq) <= n else ["|".join(seq[i:i+n]) for i in range(len(seq)-n+1)]
    return simhash_from_tokens(grams)

@dataclass
class Cluster:
    id: int
    text_fp: int
    dom_fp: int
    members: Set[str] = field(default_factory=set)  # URLs (already strip fragment)
    repr_url: str = ""                              # Representative URL

class ContentDedupeIndex:
    def __init__(self, store_path: str = "dedupe_index.json"):
        self.store_path = store_path
        self.clusters: Dict[int, Cluster] = {}
        self.next_id = 1
        self.bucket_text: Dict[Tuple[int,int], Set[int]] = {}
        self.bucket_dom: Dict[Tuple[int,int], Set[int]] = {}
        if os.path.exists(store_path):
            self._load()

    # ---------- Persistence ----------
    def _load(self):
        data = json.load(open(self.store_path, "r", encoding="utf-8"))
        self.next_id = data["next_id"]
        self.clusters = {}
        for k, v in data["clusters"].items():
            c = Cluster(
                id=int(k),
                text_fp=int(v["text_fp"]),
                dom_fp=int(v["dom_fp"]),
                members=set(v["members"]),
                repr_url=v["repr_url"]
            )
            self.clusters[c.id] = c
            self._index_cluster(c)

    def _save(self):
        data = {
            "next_id": self.next_id,
            "clusters": {
                str(cid): {
                    "text_fp": c.text_fp,
                    "dom_fp": c.dom_fp,
                    "members": sorted(list(c.members)),
                    "repr_url": c.repr_url
                } for cid, c in self.clusters.items()
            }
        }
        json.dump(data, open(self.store_path, "w", encoding="utf-8"),
                  ensure_ascii=False, indent=2)

    # ---------- Index buckets ----------
    @staticmethod
    def _split4(fp: int) -> List[int]:
        return [(fp >> (i*16)) & 0xFFFF for i in range(4)]

    def _index_cluster(self, c: Cluster):
        for i, part in enumerate(self._split4(c.text_fp)):
            self.bucket_text.setdefault((i, part), set()).add(c.id)
        for i, part in enumerate(self._split4(c.dom_fp)):
            self.bucket_dom.setdefault((i, part), set()).add(c.id)

    def _candidates(self, text_fp: int, dom_fp: int) -> Set[int]:
        cands: Set[int] = set()
        for i, part in enumerate(self._split4(text_fp)):
            cands |= self.bucket_text.get((i, part), set())
        for i, part in enumerate(self._split4(dom_fp)):
            cands |= self.bucket_dom.get((i, part), set())
        return cands

    # ---------- Core logic ----------
    def _same_content(self, tf_a: int, df_a: int, tf_b: int, df_b: int) -> bool:
        ht = hamming(tf_a, tf_b)
        hd = hamming(df_a, df_b)
        return (ht <= CONFIG["text_hamming_thresh"]) and (hd <= CONFIG["dom_hamming_thresh"])

    def _maybe_update_repr(self, c: Cluster, url_n: str):
        if c.repr_url == "":
            c.repr_url = url_n
            return
        if CONFIG["repr_policy"] == "longest":
            if len(url_n) > len(c.repr_url):
                c.repr_url = url_n
        else:  # shortest
            if len(url_n) < len(c.repr_url):
                c.repr_url = url_n

    # ---------- Single item classification (for Crawler) ----------
    def classify(self, url: str, html_str: str, driver=None) -> Dict:
        “””
        Returns:
          {
            “is_new”: True/False,     # Whether this is a “new content cluster”
            “cluster_id”: int,        # Assigned cluster
            “repr_url”: str,          # Current cluster representative URL
            “why”: { ... }            # Explanation (rule/distance/same path/URL equivalence)
          }
        Also incrementally writes this URL to the index (persistent)
        “””
        url_n = normalize_url(url)
        text = extract_main_text(html_str or "", driver=driver)
        tfp = text_simhash(text)
        dfp = dom_simhash(html_str or "", n=CONFIG["dom_n_gram"], driver=driver)

        # Debug info
        print(f"\n[Dedupe] Classifying: {url}")
        print(f"[Dedupe] Normalized: {url_n}")
        print(f"[Dedupe] Text preview: {text}")
        print(f"[Dedupe] Text length: {len(text)}")
        print(f"[Dedupe] Text fingerprint: {tfp}")
        print(f"[Dedupe] DOM fingerprint: {dfp}")

        cands = self._candidates(tfp, dfp) or set(self.clusters.keys())
        print(f"[Dedupe] Candidate clusters: {cands}")
        target_cluster: Optional[Cluster] = None
        why = {
            "rule": "new_cluster",
            "ht": None, "hd": None,
            "same_path": False, "url_strict_eq": False
        }

        for cid in cands:
            c = self.clusters[cid]
            ht = hamming(tfp, c.text_fp)
            hd = hamming(dfp, c.dom_fp)
            print(f"[Dedupe]   Comparing with cluster {cid} (repr: {c.repr_url})")
            print(f"[Dedupe]     Text hamming: {ht} (threshold: {CONFIG['text_hamming_thresh']})")
            print(f"[Dedupe]     DOM hamming: {hd} (threshold: {CONFIG['dom_hamming_thresh']})")

            if CONFIG["require_same_path"] and not _same_path_only(url_n, c.repr_url):
                print(f"[Dedupe]     Skipped: different path")
                continue
            if _url_equiv(url_n, c.repr_url):
                print(f"[Dedupe]     Matched by URL equivalence")
                target_cluster = c
                why.update({
                    "rule": "url_strict_eq",
                    "same_path": True, "url_strict_eq": True,
                    "ht": hamming(tfp, c.text_fp), "hd": hamming(dfp, c.dom_fp)
                })
                break
            if self._same_content(tfp, dfp, c.text_fp, c.dom_fp):
                print(f"[Dedupe]     Matched by content similarity")
                target_cluster = c
                why.update({
                    "rule": "text+dom",
                    "same_path": _same_path_only(url_n, c.repr_url),
                    "url_strict_eq": False,
                    "ht": hamming(tfp, c.text_fp), "hd": hamming(dfp, c.dom_fp)
                })
                break
        print(f"[Dedupe] Final: target_cluster={target_cluster.id if target_cluster else None}")

        if target_cluster is None:
            # New cluster
            cid = self.next_id
            self.next_id += 1
            c = Cluster(id=cid, text_fp=tfp, dom_fp=dfp,
                        members={url_n}, repr_url=url_n)
            self.clusters[cid] = c
            self._index_cluster(c)
            self._save()
            return {"is_new": True, "cluster_id": cid, "repr_url": c.repr_url, "why": why}
        else:
            # Merge into existing cluster
            c = target_cluster
            c.members.add(url_n)
            self._maybe_update_repr(c, url_n)
            if hamming(tfp, c.text_fp) <= CONFIG["update_text_hamming_thresh"]:
                c.text_fp = tfp
            if hamming(dfp, c.dom_fp) <= CONFIG["update_dom_hamming_thresh"]:
                c.dom_fp = dfp
            self._save()
            return {"is_new": False, "cluster_id": c.id, "repr_url": c.repr_url, "why": why}

def main():
    """
    Debug tool: test page deduplication logic

    Usage:
        python task/page_find.py

    Then enter URLs at the prompt to test
    """
    print("="*70)
    print("Page Dedupe Debug Tool")
    print("="*70)

    # Initialize driver
    print("\n[1] Initializing Chrome driver...")
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")  # Uncomment for headless mode
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--disable-xss-auditor")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(60)
    driver.set_window_size(1920, 1080)

    print("✓ Driver initialized")

    try:
        # Interactive testing
        while True:
            print("\n" + "="*70)
            url = input("\nEnter URL to test (or 'quit' to exit): ").strip()

            if url.lower() in ['quit', 'exit', 'q']:
                break

            if not url:
                continue

            # Visit page
            print(f"\n[2] Visiting: {url}")
            driver.get(url)

            # Wait for page to load
            settle_wait = 0.6
            print(f"[3] Waiting {settle_wait}s for page to settle...")
            time.sleep(settle_wait)

            # Save screenshot
            screenshot_dir = "screenshots"
            os.makedirs(screenshot_dir, exist_ok=True)
            
            # Convert URL to valid filename (replace special characters)
            safe_filename = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("#", "_").replace(":", "_")
            screenshot_path = os.path.join(screenshot_dir, f"{safe_filename}.png")
            
            driver.save_screenshot(screenshot_path)
            print(f"\n[2.5] Screenshot saved: {screenshot_path}")

            # Get page source
            html_src = driver.page_source
            print(f"\n[4] Page source length: {len(html_src)} characters")

            # Extract text
            print(f"\n[5] Extracting main text...")
            text = extract_main_text(html_src, driver)
            print(f"    Text length: {len(text)} characters")
            print(f"\n    Text preview (first 500 chars):")
            print("    " + "-"*66)
            print("    " + text[:500].replace("\n", "\n    "))
            if len(text) > 500:
                print("    ...")
            print("    " + "-"*66)

            # Compute hashes
            print(f"\n[6] Computing fingerprints...")
            text_fp = text_simhash(text)
            dom_fp = dom_simhash(html_src, n=CONFIG["dom_n_gram"], driver=driver)

            print(f"    Text SimHash: {text_fp}")
            print(f"    DOM SimHash:  {dom_fp}")

            # Extract DOM sequence (optional, for debugging)
            print(f"\n[7] DOM tag sequence:")
            dom_seq = dom_tag_sequence(html_src, driver=driver)
            print(f"    Total tags: {len(dom_seq)}")
            print(f"    First 30 tags: {' '.join(dom_seq[:30])}")
            if len(dom_seq) > 30:
                print(f"    ...")

            # Optional: print full page source (if needed)
            show_full = input("\nShow full page source? (y/N): ").strip().lower()
            if show_full == 'y':
                # print("\n[8] Full page source:")
                # print("="*70)
                # # Print first 2000 characters
                # print("=== First 2000 characters ===")
                # print(html_src[:2000])

                # # Print middle 5000 characters
                # print("\n=== Middle 5000 characters ===")
                # mid_start = len(html_src) // 2 - 2500  # 2500 before midpoint
                # mid_end = mid_start + 5000
                # print(html_src[max(0, mid_start):mid_end])

                # # Print last 2000 characters
                # print("\n=== Last 2000 characters ===")
                # print(html_src[-2000:])
                # print("="*70)

                print(html_src)

    finally:
        print("\n[Cleanup] Closing driver...")
        driver.quit()
        print("✓ Done")


if __name__ == "__main__":
    main()