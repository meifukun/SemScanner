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
    from bs4 import BeautifulSoup  # 可选；没有也能跑，会退化到正则
except Exception:
    BeautifulSoup = None

# task/page_find.py
CONFIG = {
    "require_same_path": False,   # ← 改成 False：不同 path 也参与内容相似度判断
    "dom_n_gram": 3,
    "text_hamming_thresh": 1,
    "dom_hamming_thresh": 1,
    "update_text_hamming_thresh": 2,
    "update_dom_hamming_thresh": 6,
    "repr_policy": "shortest",
    "print_singletons": False,
}

# def _strip_fragment(u: str) -> str:
#     """移除 fragment，但对于 SPA 路由（#/xxx）保留"""
#     pu = urlparse(u)
#     # 如果 fragment 看起来像路由路径（以 / 开头），保留它
#     if pu.fragment and pu.fragment.startswith('/'):
#         return u  # 保留原样
#     return urlunparse((pu.scheme, pu.netloc, pu.path or "/", pu.params, pu.query, ""))

from urllib.parse import urlparse, urlunparse

def _strip_fragment(u: str) -> str:
    """
    只在 '#' 出现在 '?' 后面的情况下移除 fragment。
    否则保持 URL 完全不变。
    """

    # 找到问号和井号的位置（不存在则为 -1）
    q = u.find("?")
    h = u.find("#")

    # 情况1：没有 '?' => 保持原样
    if q == -1:
        return u

    # 情况2：有 '?'，但 '#' 在 '?' 前 => 保持原样
    if h == -1 or h < q:
        return u

    # 情况3： '#' 出现在 '?' 后 => 执行 strip fragment
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
    提取主要文本内容
    
    Args:
        html_str: HTML源码（用于fallback）
        driver: Selenium WebDriver（可选，用于获取可见文本）
    
    Returns:
        str: 清理后的文本
    """
    # 🆕 如果提供了driver，使用JavaScript获取可见文本（快速方案）
    if driver:
        try:
            visible_text = driver.execute_script("""
                // 递归获取可见元素的文本
                function getVisibleText(el) {
                    if (!el) return '';
                    
                    // 检查元素是否可见
                    const style = window.getComputedStyle(el);
                    if (style.display === 'none' || 
                        style.visibility === 'hidden' || 
                        parseFloat(style.opacity) === 0) {
                        return '';
                    }
                    
                    // 排除script/style/noscript
                    const tagName = el.tagName ? el.tagName.toLowerCase() : '';
                    if (['script', 'style', 'noscript', 'template'].includes(tagName)) {
                        return '';
                    }
                    
                    // 排除常见非内容区域
                    const className = el.className || '';
                    const classStr = typeof className === 'string' ? className : '';
                    if (/header|footer|nav|ads|ad-|sidebar|breadcrumb|login|subscribe/i.test(classStr)) {
                        return '';
                    }
                    
                    // 获取文本节点
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
                # 清理文本
                text = html.unescape(visible_text)
                text = re.sub(r'\s+', ' ', text).strip()
                text = re.sub(r'\b\d{1,2}:\d{2}(:\d{2})?\b', ' <TIME> ', text)
                text = re.sub(r'\b\d{4}[-/]\d{1,2}[-/]\d{1,2}\b', ' <DATE> ', text)
                return text
            else:
                print("    [Warning: driver returned empty text, falling back to HTML parsing]")
        except Exception as e:
            print(f"    [Warning: driver extraction failed ({e}), falling back to HTML parsing]")
    
    # 🔄 Fallback：使用原来的HTML解析方法
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
    提取DOM标签序列
    
    Args:
        html_str: HTML源码（用于fallback）
        driver: Selenium WebDriver（可选，用于只获取可见元素的DOM结构）
    
    Returns:
        List[str]: 标签序列
    """
    # 🆕 如果提供了driver，使用JavaScript获取可见元素的DOM结构
    if driver:
        try:
            print("    [Using driver to extract visible DOM structure]")
            visible_tags = driver.execute_script("""
                // 递归遍历可见元素，收集标签序列
                function getVisibleDOMSequence(el, sequence) {
                    if (!el || !el.tagName) return;
                    
                    // 检查元素是否可见
                    const style = window.getComputedStyle(el);
                    if (style.display === 'none' || 
                        style.visibility === 'hidden' || 
                        parseFloat(style.opacity) === 0) {
                        return;
                    }
                    
                    const tagName = el.tagName.toLowerCase();
                    
                    // 排除script/style/noscript
                    if (['script', 'style', 'noscript', 'template'].includes(tagName)) {
                        return;
                    }
                    
                    // 排除常见非内容区域
                    const className = el.className || '';
                    const classStr = typeof className === 'string' ? className : '';
                    if (/header|footer|nav|ads|ad-|sidebar|breadcrumb|login|subscribe/i.test(classStr)) {
                        return;
                    }
                    
                    // 添加开始标签
                    sequence.push(tagName);
                    
                    // 遍历子元素
                    for (let child of el.children) {
                        getVisibleDOMSequence(child, sequence);
                    }
                    
                    // 添加结束标签（排除自闭合标签）
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
    
    # 🔄 Fallback：使用原来的HTML解析方法
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
    members: Set[str] = field(default_factory=set)  # URLs（已 strip fragment）
    repr_url: str = ""                              # 代表 URL

class ContentDedupeIndex:
    def __init__(self, store_path: str = "dedupe_index.json"):
        self.store_path = store_path
        self.clusters: Dict[int, Cluster] = {}
        self.next_id = 1
        self.bucket_text: Dict[Tuple[int,int], Set[int]] = {}
        self.bucket_dom: Dict[Tuple[int,int], Set[int]] = {}
        if os.path.exists(store_path):
            self._load()

    # ---------- 持久化 ----------
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

    # ---------- 索引桶 ----------
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

    # ---------- 核心逻辑 ----------
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

    # ---------- 单条判定（给 Crawler 用） ----------
    def classify(self, url: str, html_str: str, driver=None) -> Dict:
        """
        返回：
          {
            "is_new": True/False,     # 是否“新内容簇”
            "cluster_id": int,        # 归入的簇
            "repr_url": str,          # 当前簇代表 URL
            "why": { ... }            # 解释（规则/距离/同路径/URL等价）
          }
        同时会把该 URL 增量写入索引（持久化）
        """
        url_n = normalize_url(url)
        text = extract_main_text(html_str or "", driver=driver)
        tfp = text_simhash(text)
        dfp = dom_simhash(html_str or "", n=CONFIG["dom_n_gram"], driver=driver)

        # 👇 添加调试信息
        print(f"\n[Dedupe] Classifying: {url}")
        print(f"[Dedupe] Normalized: {url_n}")
        print(f"[Dedupe] Text preview: {text}")
        print(f"[Dedupe] Text length: {len(text)}")
        print(f"[Dedupe] Text fingerprint: {tfp}")
        print(f"[Dedupe] DOM fingerprint: {dfp}")

        cands = self._candidates(tfp, dfp) or set(self.clusters.keys())
        print(f"[Dedupe] Candidate clusters: {cands}")  # 👈 加这行
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
                print(f"[Dedupe]     ✅ Matched by URL equivalence")  # 👈 加这行
                target_cluster = c
                why.update({
                    "rule": "url_strict_eq",
                    "same_path": True, "url_strict_eq": True,
                    "ht": hamming(tfp, c.text_fp), "hd": hamming(dfp, c.dom_fp)
                })
                break
            if self._same_content(tfp, dfp, c.text_fp, c.dom_fp):
                print(f"[Dedupe]     ✅ Matched by content similarity")  # 👈 加这行
                target_cluster = c
                why.update({
                    "rule": "text+dom",
                    "same_path": _same_path_only(url_n, c.repr_url),
                    "url_strict_eq": False,
                    "ht": hamming(tfp, c.text_fp), "hd": hamming(dfp, c.dom_fp)
                })
                break
        print(f"[Dedupe] Final: target_cluster={target_cluster.id if target_cluster else None}")  # 👈 加这行

        if target_cluster is None:
            # 新簇
            cid = self.next_id
            self.next_id += 1
            c = Cluster(id=cid, text_fp=tfp, dom_fp=dfp,
                        members={url_n}, repr_url=url_n)
            self.clusters[cid] = c
            self._index_cluster(c)
            self._save()
            return {"is_new": True, "cluster_id": cid, "repr_url": c.repr_url, "why": why}
        else:
            # 并入旧簇
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
    Debug 工具：测试页面去重逻辑
    
    使用方法：
        python task/page_find.py
    
    然后在提示符下输入 URL 进行测试
    """
    print("="*70)
    print("Page Dedupe Debug Tool")
    print("="*70)

    # 初始化 driver
    print("\n[1] Initializing Chrome driver...")
    chrome_options = webdriver.ChromeOptions()
    chrome_options.add_argument("--headless")  # 取消注释可以无头模式
    chrome_options.add_argument("--disable-web-security")
    chrome_options.add_argument("--allow-running-insecure-content")
    chrome_options.add_argument("--disable-xss-auditor")

    service = Service(ChromeDriverManager().install())
    driver = webdriver.Chrome(service=service, options=chrome_options)
    driver.set_page_load_timeout(60)
    driver.set_window_size(1920, 1080)

    print("✓ Driver initialized")

    try:
        # 交互式测试
        while True:
            print("\n" + "="*70)
            url = input("\nEnter URL to test (or 'quit' to exit): ").strip()

            if url.lower() in ['quit', 'exit', 'q']:
                break

            if not url:
                continue

            # 访问页面
            print(f"\n[2] Visiting: {url}")
            driver.get(url)

            # 等待页面加载
            settle_wait = 0.6
            print(f"[3] Waiting {settle_wait}s for page to settle...")
            time.sleep(settle_wait)

            # 保存截图
            screenshot_dir = "screenshots"
            os.makedirs(screenshot_dir, exist_ok=True)
            
            # 将URL转换为合法文件名（替换特殊字符）
            safe_filename = url.replace("://", "_").replace("/", "_").replace("?", "_").replace("&", "_").replace("#", "_").replace(":", "_")
            screenshot_path = os.path.join(screenshot_dir, f"{safe_filename}.png")
            
            driver.save_screenshot(screenshot_path)
            print(f"\n[2.5] Screenshot saved: {screenshot_path}")

            # 获取 page source
            html_src = driver.page_source
            print(f"\n[4] Page source length: {len(html_src)} characters")

            # 提取文本
            print(f"\n[5] Extracting main text...")
            text = extract_main_text(html_src, driver)
            print(f"    Text length: {len(text)} characters")
            print(f"\n    Text preview (first 500 chars):")
            print("    " + "-"*66)
            print("    " + text[:500].replace("\n", "\n    "))
            if len(text) > 500:
                print("    ...")
            print("    " + "-"*66)

            # 计算哈希
            print(f"\n[6] Computing fingerprints...")
            text_fp = text_simhash(text)
            dom_fp = dom_simhash(html_src, n=CONFIG["dom_n_gram"], driver=driver)

            print(f"    Text SimHash: {text_fp}")
            print(f"    DOM SimHash:  {dom_fp}")

            # 提取 DOM 序列（可选，用于调试）
            print(f"\n[7] DOM tag sequence:")
            dom_seq = dom_tag_sequence(html_src, driver=driver)
            print(f"    Total tags: {len(dom_seq)}")
            print(f"    First 30 tags: {' '.join(dom_seq[:30])}")
            if len(dom_seq) > 30:
                print(f"    ...")

            # 可选：打印完整的 page source（如果需要）
            show_full = input("\nShow full page source? (y/N): ").strip().lower()
            if show_full == 'y':
                # print("\n[8] Full page source:")
                # print("="*70)
                # # 打印开头2000字符
                # print("=== 开头 2000 字符 ===")
                # print(html_src[:2000])

                # # 打印中间5000字符
                # print("\n=== 中间 5000 字符 ===")
                # mid_start = len(html_src) // 2 - 2500  # 从中点往前2500
                # mid_end = mid_start + 5000
                # print(html_src[max(0, mid_start):mid_end])

                # # 打印最后2000字符
                # print("\n=== 最后 2000 字符 ===")
                # print(html_src[-2000:])
                # print("="*70)

                print(html_src)

    finally:
        print("\n[Cleanup] Closing driver...")
        driver.quit()
        print("✓ Done")


if __name__ == "__main__":
    main()