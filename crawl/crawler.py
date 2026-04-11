from __future__ import annotations
from typing import List, Set, Dict
import time, json, os
import hashlib
import re
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed, wait, FIRST_COMPLETED  # concurrency support
from selenium.webdriver.common.by import By
from urllib.parse import urlsplit
from app_info.models import PageInfo, Edge, NetworkRequest
from app_info.webapp_store import WebAppStore
from capture.network_capture import NetworkCapture
from crawl.sensors import Sensors
from crawl.Actuators import Actuators
from crawl.Bridge import Bridge
from task.task_queue import TaskQueue
from task.task_generator import TaskGenerator
from crawl.tracer import ExecutionTracer
from task.page_find import ContentDedupeIndex
import random
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException

class Crawler:
    def __init__(self, driver, client, initial_url, target_domain: str, store_root: str = "output/webapp_store"):
        self.initial_url = initial_url
        self.target_domain = target_domain
        self.driver = driver

        # Read from environment variable whether to use improved locator strategy (enabled by default)
        use_improved_locator = os.getenv('USE_IMPROVED_LOCATOR', 'true').lower() == 'true'
        if use_improved_locator:
            print("=" * 60)
            print("Improved element locator strategy enabled")
            print("   - Fix: normalization issue with href/src and other URL attributes")
            print("   - Enhancement: multi-level fallback mechanism")
            print("   - Improvement: smart indexing for duplicate elements")
            print("=" * 60)

        self.sensors = Sensors(driver, use_improved_locator=use_improved_locator)
        self.acts = Actuators(self.sensors)
        self.bridge = Bridge(sensors=self.sensors, actuators=self.acts, client=client)
        self.root_dir = store_root
        self.store = WebAppStore(root_dir=store_root)
        self.task_queue = TaskQueue(path=os.path.join(store_root, "tasks_queue.jsonl"))
        self.task_gen = TaskGenerator(client=client, task_queue=self.task_queue, root_dir=store_root)

        self.network_capture = NetworkCapture(driver)

        # tracer
        self.tracer = ExecutionTracer(
            store=self.store,
            network_capture=self.network_capture,
            on_new_page=self._on_new_page_discovered,
            construct_edge=self.construct_edge
        )
        self.bridge.set_tracer(self.tracer, self.task_queue, self.store)  # pass in store

        # Page content deduplication index (persisted to OUTPUT_ROOT; falls back to current directory if empty)
        dedupe_store = os.path.join(store_root, "dedupe_index.json")
        self.content_index = ContentDedupeIndex(store_path=dedupe_store)

        # Statistics
        self.visited_urls: Set[str] = set()  # visited pages
        self.settle_wait: float = 0.6  # page load wait time
        self.stats = {'pages_discovered': 0, 'edges_created': 0, 'links_collected': 0, 'requests_captured': 0}

        # URL blacklist: URLs containing these keywords will be skipped
        self.url_blacklist = [
            'logout',      # logout link
            'signout',     # logout link
            'sign-out',    # logout link
            'logoff',      # logout link
            'password',
            'delete_post',
            # More keywords can be added here...
        ]

        # Reuse TaskGenerator's navigation log
        self._navlog = getattr(self.task_gen, "_log_nav", lambda *a, **k: None)

    # Request mapping and processed markers
        self.request_mapping = {}  # (method, url) -> full_request_data
        # ID mapping table
        self.request_id_map = {}   # request_id -> full_request_data

        self.processed_requests = set()  # requests already processed by attack planning
        self._build_request_mapping()

        # Screenshot save directory (for debugging and observing deduplication effects)
        self.screenshot_dir = Path(store_root) / "crawl_screenshots"
        self.screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.unique_screenshot_dir = self.screenshot_dir / "unique_pages"
        self.duplicate_screenshot_dir = self.screenshot_dir / "duplicate_pages"
        self.unique_screenshot_dir.mkdir(parents=True, exist_ok=True)
        self.duplicate_screenshot_dir.mkdir(parents=True, exist_ok=True)

        # Screenshot counter and mapping
        self.unique_page_counter = 0  # unique page counter
        self.duplicate_page_counter = 0  # duplicate page counter
        self.url_to_screenshot_id = {}  # URL -> screenshot ID mapping (for duplicate page reference)

    # [crawler.py] Add new method
    def _generate_request_id(self, dedup_key: tuple) -> str:
        """Generate a unique short hash ID based on the dedup key"""
        # Convert tuple to string for hashing, ensuring stability
        key_str = str(dedup_key).encode('utf-8')
        return hashlib.md5(key_str).hexdigest()[:8]  # Return 8-char hash, e.g. "a1b2c3d4"

    def _url_to_filename(self, url: str) -> str:
        """
        Convert a URL to a valid filename

        Strategy:
        1. Remove protocol prefix (http://, https://)
        2. Replace special characters with underscores
        3. If filename is too long (>200 chars), use MD5 hash + prefix

        Args:
            url: Original URL

        Returns:
            A valid filename (without extension)
        """
        # Remove protocol
        filename = re.sub(r'^https?://', '', url)

        # Replace special characters with underscores
        filename = re.sub(r'[^\w\-.]', '_', filename)

        # Remove consecutive underscores
        filename = re.sub(r'_+', '_', filename)

        # Remove leading/trailing underscores
        filename = filename.strip('_')

        # If filename is too long, use hash
        if len(filename) > 200:
            # Use MD5 hash + first 50 chars as prefix
            url_hash = hashlib.md5(url.encode('utf-8')).hexdigest()[:8]
            filename = f"{filename[:50]}_{url_hash}"

        return filename

    def _save_crawler_screenshot(self, url: str, is_unique: bool, counter: int, ref_id: int = None) -> bool:
        """
        Save a screenshot during the crawl phase (for debugging deduplication logic)

        Args:
            url: Current URL being visited
            is_unique: Whether this is a unique page
            counter: Counter (sequence number for unique or duplicate pages)
            ref_id: If duplicate, the referenced unique page ID

        Returns:
            True if screenshot saved successfully, False otherwise

        Filename format:
            - Unique page: 001_url.png
            - Duplicate page: 001_url_dup_of_005.png (indicates duplicate of unique page #5)
        """
        if not self.driver:
            return False

        try:
            # Generate base filename
            base_filename = self._url_to_filename(url)

            # Choose directory and filename based on uniqueness
            if is_unique:
                # Unique page: save to unique_pages/
                filename = f"{counter:03d}_{base_filename}.png"
                screenshot_path = self.unique_screenshot_dir / filename
                print(f"  [Unique] Screenshot #{counter}: {filename}")
            else:
                # Duplicate page: save to duplicate_pages/, noting the referenced unique page
                if ref_id is not None:
                    filename = f"{counter:03d}_{base_filename}_dup_of_{ref_id:03d}.png"
                else:
                    filename = f"{counter:03d}_{base_filename}_duplicate.png"
                screenshot_path = self.duplicate_screenshot_dir / filename
                print(f"  [Duplicate] Screenshot #{counter}: {filename}" +
                      (f" (duplicate of unique page #{ref_id})" if ref_id else ""))

            # Save screenshot
            success = self.driver.save_screenshot(str(screenshot_path))

            if not success:
                print(f"  Warning: Screenshot failed: {filename}")
                return False

            return True

        except Exception as e:
            print(f"  Warning: Screenshot error: {e}")
            return False

    def _preprocess_url_for_dedup(self, url: str) -> str:
        """
        Preprocess URL for deduplication: only remove the fragment (#) part after the query (?)

        Strategy:
        - SPA URL (# before ?): http://host/#/search?q=juice -> keep unchanged
        - Traditional URL (? before #): http://host/path?data=123#section -> http://host/path?data=123
        - No query mark: http://host/#/page -> keep unchanged

        Args:
            url: Original URL

        Returns:
            Preprocessed URL
        """
        # Find the position of the first ?
        question_pos = url.find('?')

        if question_pos == -1:
            # No query mark, keep as is (could be http://host/#/page)
            return url

        # Find the position of # after the query mark
        hash_pos = url.find('#', question_pos)

        if hash_pos == -1:
            # No # after the query mark, keep as is
            return url

        # Remove the # and everything after it that follows the query mark
        return url[:hash_pos]

    def _extract_form_schema(self, form_body: str) -> str:
        """
        Extract parameter names from form-data format

        Examples:
            "name=foo&age=18" -> "age,name"
            "key1=val1&key2=val2&key3=val3" -> "key1,key2,key3"
        """
        try:
            keys = []
            for pair in form_body.split("&"):
                if "=" in pair:
                    key = pair.split("=", 1)[0]  # Only split on the first =
                    keys.append(key)

            if not keys:
                return "form:empty"

            return ",".join(sorted(keys))
        except Exception:
            return "form:invalid"

    def _extract_body_schema(self, body) -> str:
        """
        Extract the parameter name structure from the body (only look at names, not values)

        Used for deduplication: requests with the same structure but different values are considered duplicates

        Examples:
            {"name": "foo", "age": 18}
                -> "age,name"

            [{"id": 1, "name": "A"}, {"id": 2, "name": "B"}]
                -> "[id,name]"

            []
                -> "[]"

            "name=foo&age=18"  (form-data)
                -> "age,name"

        Args:
            body: Request body (may be string, dict, list, etc.)

        Returns:
            Normalized string of parameter names
        """
        if body is None:
            return ""

        try:
            # 1. Try to parse as JSON
            if isinstance(body, str):
                try:
                    data = json.loads(body)
                except json.JSONDecodeError:
                    # Could be form-data format (name=value&key=value)
                    return self._extract_form_schema(body)
            else:
                data = body

            # 2. Extract schema based on data type
            if isinstance(data, dict):
                # Dict: extract all top-level keys, sort and join
                if not data:  # empty dict
                    return "{}"
                return ",".join(sorted(data.keys()))

            elif isinstance(data, list):
                if not data:  # empty array
                    return "[]"

                # Array: take the structure of the first element
                first_elem = data[0]
                if isinstance(first_elem, dict):
                    # Array elements are dicts
                    keys = ",".join(sorted(first_elem.keys()))
                    return f"[{keys}]"
                else:
                    # Array elements are simple types
                    return f"[{type(first_elem).__name__}]"

            else:
                # Other types (string, number, etc.)
                return f"primitive:{type(data).__name__}"

        except Exception as e:
            # Parse failed, return a marker
            # Use body length for coarse-grained distinction
            body_str = str(body)
            if len(body_str) == 0:
                return "empty"
            elif len(body_str) < 10:
                return "tiny"
            elif len(body_str) < 100:
                return "small"
            else:
                return "large"

    def _make_dedup_key(self, method: str, url: str, body=None):
        """
        Generate request dedup key (fix: supports SPA URL + POST body structure)

        Strategy:
        - GET requests: use (method, path, set of param names) as key
          e.g.: GET /api?id=1&name=foo -> ("GET", "/api", frozenset({"id", "name"}))
          SPA: GET http://host/#/search?q=juice -> ("GET", "http://host/#/search", frozenset({"q"}))
        - POST/PUT/PATCH requests: use (method, url, body_schema) as key
          e.g.: POST /api + {"name":"A"} -> ("POST", "/api", "name")
               POST /api + {"name":"B"} -> ("POST", "/api", "name")  # same!
               POST /api + {"name":"A","age":18} -> ("POST", "/api", "age,name")  # different!
        - Other requests: use full URL
          e.g.: DELETE /api -> ("DELETE", "/api")

        Args:
            method: HTTP method
            url: Full URL
            body: Request body (optional, for POST/PUT/PATCH)

        Returns:
            Dedup key (tuple)
        """
        from urllib.parse import urlparse, parse_qs

        # Preprocessing: only remove # after ? (keep # before ? cases)
        processed_url = self._preprocess_url_for_dedup(url)

        if method.upper() == "GET":
            parsed = urlparse(processed_url)
            # Path part (including domain and SPA path in fragment)
            # For http://host/#/search?q=juice, parsed.fragment = "/search?q=juice"
            if parsed.fragment and '?' in parsed.fragment:
                # SPA scenario: fragment contains path and params
                # Extract the part before ? in fragment as path
                fragment_path = parsed.fragment.split('?')[0]
                path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{fragment_path}"

                # Extract params after ? in fragment
                fragment_query = parsed.fragment.split('?', 1)[1] if '?' in parsed.fragment else ""
                fragment_params = parse_qs(fragment_query)
                param_names = frozenset(fragment_params.keys()) if fragment_params else frozenset()
            else:
                # Traditional scenario or SPA without params
                if parsed.fragment:
                    # Has fragment but no params (e.g. #/page)
                    path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}#{parsed.fragment}"
                else:
                    # No fragment
                    path = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"

                # Extract URL query params (traditional params after ?)
                query_params = parse_qs(parsed.query)
                param_names = frozenset(query_params.keys()) if query_params else frozenset()

            return (method, path, param_names)
        elif method.upper() in ["POST", "PUT", "PATCH"]:
            # For POST/PUT/PATCH, consider the body's parameter structure
            body_schema = self._extract_body_schema(body)
            return (method, processed_url, body_schema)
        else:
            # Other requests use full URL
            return (method, processed_url)

    def _build_request_mapping(self):
        """
        Build request mapping table: dedup_key -> full request data

        Fix: use full dedup_key as mapping key, supporting distinction of POST requests with different body_schema
        """
        self.request_mapping = {}
        self.request_id_map = {}  # Clear ID mapping

        # Collect requests from all trace files
        for trace_file in self.store.traces_dir.glob("task_*.json"):
            try:
                trace_data = json.loads(trace_file.read_text(encoding="utf-8"))
                for step in trace_data.get("steps", []):
                    for req in step.get("network_requests", []):
                        method = req.get("method", "")
                        url = req.get("url", "")
                        body = req.get("body")
                        # Use full dedup_key
                        key = self._make_dedup_key(method, url, body)
                        if key not in self.request_mapping:
                            self.request_mapping[key] = req
                            req_id = self._generate_request_id(key)
                            self.request_id_map[req_id] = req
            except Exception as e:
                print(f"[Warning] Error building request mapping: {e}")

        # Collect from page requests
        for page in self.store.pages.values():
            for req in page.network_requests:
                # Use full dedup_key
                key = self._make_dedup_key(req.method, req.url, req.body)
                if key not in self.request_mapping:
                    data = req.to_dict()
                    self.request_mapping[key] = data
                    req_id = self._generate_request_id(key)
                    self.request_id_map[req_id] = data

    def lookup_request(self, method: str, url: str, body=None):
        """
        Look up full request data by method, url, and body

        Fix: use full dedup_key for lookup, supporting distinction of POST requests with different body_schema

        Args:
            method: HTTP method, e.g. "GET"
            url: Full URL
            body: Request body (optional, for POST/PUT/PATCH)

        Returns:
            Full request data dict including headers, body, response, etc., or None if not found
        """
        key = self._make_dedup_key(method, url, body)
        return self.request_mapping.get(key)

    def mark_request_processed(self, method: str, url: str, body=None):
        """Mark request as processed (using new dedup key)"""
        key = self._make_dedup_key(method, url, body)
        self.processed_requests.add(key)

    def is_request_processed(self, method: str, url: str, body=None) -> bool:
        """Check if request has been processed (using new dedup key)"""
        key = self._make_dedup_key(method, url, body)
        return key in self.processed_requests

    def _is_url_blacklisted(self, url: str) -> bool:
        """
        Check if URL is in the blacklist

        Args:
            url: URL to check

        Returns:
            True if URL contains a blacklisted keyword, False otherwise
        """
        url_lower = url.lower()
        for keyword in self.url_blacklist:
            if keyword.lower() in url_lower:
                return True
        return False


    # Page content deduplication function
    def _is_new_content_page(self, url: str) -> bool:
        """Determine if page is a 'new content cluster' based on actual HTML. Falls back to True on error (avoid missing pages)."""
        try:
            html_src = self.driver.page_source
            res = self.content_index.classify(url, html_src, driver=self.driver)
            return bool(res["is_new"])
        except Exception as e:
            print(f"[Dedupe] classify error for {url}: {e}")
            return True

    # Two callback functions used by the tracer
    def construct_edge(self, url):
        # Collect all links on this page
        all_links = self._collect_all_page_links()
        self._add_discovered_links_to_graph(url, all_links)

    def _add_discovered_links_to_graph(self, from_url: str, links: List[str]):
        """Add discovered links to the graph as potential nodes"""
        for link in links:
            # Create a "discovered" edge, indicating this link was found on the page but not necessarily visited
            if not self.store.has_edge(from_url, link):
                edge = Edge(
                    from_url=from_url,
                    to_url=link,
                    via_action_id=-1,  # -1 indicates not actually clicked
                    via_repr="link",
                    jump_kind="discovered",
                )
                self.store.add_edge(edge)

    def _on_new_page_discovered(self, url: str):
        """When a new page is discovered, collect page info and generate tasks"""
        print(f"[Crawler] New page discovered: {url}")

        # Wait for page to stabilize
        time.sleep(self.settle_wait)

        # Get dedup classification result (classify before checking)
        try:
            html_src = self.driver.page_source
            dedup_result = self.content_index.classify(url, html_src, driver=self.driver)
            is_new = bool(dedup_result.get("is_new", True))
        except Exception as e:
            print(f"[Dedupe] classify error for {url}: {e}")
            is_new = True
            dedup_result = {}

        # Save screenshot (save regardless of whether duplicate)
        if is_new:
            # Unique page: save to unique_pages/
            self.unique_page_counter += 1
            self._save_crawler_screenshot(url, is_unique=True, counter=self.unique_page_counter)
            self.url_to_screenshot_id[url] = self.unique_page_counter
        else:
            # Duplicate page: save to duplicate_pages/, noting the referenced unique page
            self.duplicate_page_counter += 1
            cluster_id = dedup_result.get("cluster_id")
            repr_url = dedup_result.get("repr_url")
            ref_id = self.url_to_screenshot_id.get(repr_url)
            self._save_crawler_screenshot(url, is_unique=False, counter=self.duplicate_page_counter, ref_id=ref_id)
            print(f"[Crawler] Duplicate page content, skipping: {url} (cluster: {cluster_id}, repr: {repr_url})")
            return

        # Collect page info
        self._collect_page_info(url)

        # Generate logical tasks
        page = self.store.get_page(url)
        if page:
            title = (self.driver.title or "").strip()
            reasoning, task_descriptions = self.task_gen.generate_logic_for_page(page)
            page.description = f"Title: {title}\nDescription: {reasoning}"
            page.logic_tasks = task_descriptions
            self.store.add_page(page, persist=True)

            print(f"[Crawler] New page stored: {url}, generated {len(task_descriptions)} tasks")

    def _get_urls_from_edges(self) -> List[str]:
        """
        Read all URLs from edge files for traversal

        Returns:
            Deduplicated URL list, excluding visited and blacklisted URLs
        """
        all_urls = set()

        # 1. Collect URLs from all edges
        for edge in self.store.edges:
            all_urls.add(edge.from_url)
            all_urls.add(edge.to_url)

        # 2. Filter visited URLs (from store)
        visited = set(self.store.pages.keys())
        pending_urls = all_urls - visited

        # 3. Filter blacklisted URLs
        filtered_urls = [
            url for url in pending_urls
            if not self._is_url_blacklisted(url)
        ]

        print(f"[Crawl] Edge statistics:")
        print(f"  - Total URLs: {len(all_urls)}")
        print(f"  - Visited: {len(visited)}")
        print(f"  - Pending: {len(pending_urls)}")
        print(f"  - After filtering: {len(filtered_urls)}")

        return filtered_urls

    def _get_new_urls_from_edges(self, visited_urls: set, nav_queue: list) -> List[str]:
        """
        Get newly discovered URLs from edges (excluding visited and queued ones)

        Args:
            visited_urls: Set of visited URLs
            nav_queue: List of URLs currently in the queue

        Returns:
            List of newly discovered URLs
        """
        all_urls = set()

        # Collect URLs from all edges
        for edge in self.store.edges:
            all_urls.add(edge.from_url)
            all_urls.add(edge.to_url)

        # Filter: exclude visited, queued, stored, and blacklisted URLs
        nav_queue_set = set(nav_queue)
        stored_urls = set(self.store.pages.keys())

        new_urls = [
            url for url in all_urls
            if url not in visited_urls
            and url not in nav_queue_set
            and url not in stored_urls
            and not self._is_url_blacklisted(url)
        ]

        return new_urls

    # Crawl, build initial tasks and semantic graph
    def _collect_all_page_links(self) -> List[str]:
        """Collect all links on the page (for breadth-first exploration)"""
        links = set()
        try:
            elements = self.driver.find_elements(By.TAG_NAME, 'a')
            for elem in elements:
                try:
                    href = elem.get_attribute('href')
                    if href and href.strip():
                        # Normalize URL
                        normalized = href.strip()
                        # Add to link set
                        if self.target_domain in normalized:
                            links.add(normalized)
                except Exception:
                    continue
        except Exception as e:
            print(f"[Crawler] Failed to collect links: {e}")

        return list(links)

    def _add_page_to_store(self, url: str, outgoing_links: List[str], network_requests: List[NetworkRequest], abstract_page: str):
        """Add page info to the store"""
        page_info = PageInfo(
            url=url,
            title=self.driver.title.strip(),
            abstract_page=abstract_page,
            outgoing_links=outgoing_links,
            network_requests=network_requests,
            actions_mapping=dict(self.sensors.actions_mapping.mapping),  # Save element mapping
            event_mapping=dict(self.sensors.event_mapping.mapping)  # Save event mapping
        )
        self.store.add_page(page_info, persist=False)

    def _collect_page_info(self, url: str):
        """Collect all page info including network requests, links and abstract semantics"""
        # Capture network requests
        captured_requests = self.network_capture.capture_current(url, exclude_static=True)
        network_requests = [NetworkRequest(
                method=req.get('method', ''),
                url=req.get('url', ''),
                headers=req.get('headers', {}),
                query_params=req.get('query_params', {}),
                body=req.get('body'),
                response_status=req.get('response', {}).get('status'),
                response_headers=req.get('response', {}).get('headers', {}),
                response_body=req.get('response', {}).get('body'),
            ) for req in captured_requests]

        # Collect all links on the page
        outgoing_links = self._collect_all_page_links()

        # Get page abstract semantics
        self.sensors.update_abstract_page()
        abstract = self.sensors.get_abstract_page()

        # Store this page info, including abstract semantics
        self._add_page_to_store(url, outgoing_links, network_requests, abstract)

    def crawl(self, max_pages: int = 1000, time_limit: int = 900, use_edges: bool = True, max_llm_workers: int = 20):
        """
        Start the crawler, with time and link count limits (optimized: parallel LLM tasks + screenshot saving)

        Args:
            max_pages: Maximum number of pages to visit
            time_limit: Time limit (seconds)
            use_edges: Whether to read URLs from edge files for traversal (default True for dynamic loading from edges)
            max_llm_workers: Maximum concurrency for LLM tasks (default 20)

        New features:
            - Automatically saves screenshots during crawl phase for debugging deduplication logic
            - Screenshot save location: {store_root}/crawl_screenshots/
            - unique_pages/: unique page screenshots (format: 001_url.png)
            - duplicate_pages/: duplicate page screenshots (format: 001_url_dup_of_005.png)
            - Duplicate page filenames include the referenced unique page ID for easy comparison
        """
        nav_queue = [self.initial_url]
        visited_urls = set()
        start_time = time.time()

        # Concurrent LLM task management
        llm_futures = []  # Store all pending LLM Future objects
        pending_limit = max_llm_workers * 2  # Allow max 40 pending tasks to avoid memory explosion

        # Create LLM thread pool
        llm_executor = ThreadPoolExecutor(max_workers=max_llm_workers)

        # Debug: priority URL for processing
        debug_priority_url = "not used for now"
        # debug_priority_url = "http://localhost:4328/settings#notifications"
        # debug_priority_url = "http://127.0.0.1:4325/dashboard/show"

        # BFS control variables
        bfs_limit = 30  # First 30 visits in sequential order
        bfs_count = 0  # Number of sequentially visited pages

        try:
            # Fix: ensure initial page content is added to dedup index
            if self.store.has_page(self.initial_url):
                print(f"[Crawl] Initial page already in store, adding to dedupe index")
                try:
                    self.driver.get(self.initial_url)
                    time.sleep(self.settle_wait)
                    html_src = self.driver.page_source
                    self.content_index.classify(self.initial_url, html_src, driver=self.driver)
                except Exception as e:
                    print(f"[Crawl] Failed to add initial page to dedupe: {e}")

            while nav_queue:
                # Debug: prioritize specific URL
                if debug_priority_url in nav_queue:
                    current_url = debug_priority_url
                    nav_queue.remove(debug_priority_url)
                    print(f"[DEBUG] Prioritizing target URL: {current_url}")
                else:
                    # current_url = nav_queue.pop(0)
                    # First 30 visits in sequential order
                    if bfs_count < bfs_limit:
                        current_url = nav_queue.pop(0)  # Sequential traversal
                        bfs_count += 1
                    else:
                        # Then start random selection
                        idx = random.randrange(len(nav_queue))
                        current_url = nav_queue.pop(idx)

                # Blacklist check
                if self._is_url_blacklisted(current_url):
                    self._navlog(f"[Crawl] URL in blacklist, skipping: {current_url}")
                    continue

                if self.store.has_page(current_url) or current_url in visited_urls:
                    self._navlog(f"[Crawl] Page already processed: {current_url}")
                    continue

                # 1. Get current page info
                self.network_capture.clear_requests()
                # self.driver.get(current_url)
                # print("Current page", current_url)
                # time.sleep(self.settle_wait)
                # visited_urls.add(current_url)

                try:
                    self.driver.get(current_url)
                    print("Current page", current_url)
                    time.sleep(self.settle_wait)
                    visited_urls.add(current_url)

                    # Try to get page source (if a popup appeared earlier, this will usually throw an exception)
                    html_src = self.driver.page_source

                except UnexpectedAlertPresentException as e:
                    # Caught a popup
                    alert_text = getattr(e, 'alert_text', 'Unknown')
                    print(f"[Crawler] Visiting {current_url} triggered a popup, skipping this page. Popup content: {alert_text}")

                    # Critical: must accept/close the popup, otherwise the Driver will be in a deadlock state
                    try:
                        alert = self.driver.switch_to.alert
                        alert.accept()
                    except NoAlertPresentException:
                        pass # The popup may have already closed automatically when the exception was thrown

                    # Skip current iteration, don't do dedup, screenshot, or LLM tasks
                    continue

                except Exception as e:
                    print(f"[Crawler] Other error visiting page: {current_url} - {e}")
                    continue

                # Content deduplication check
                # if not self._is_new_content_page(current_url):
                #     self._navlog(f"[Crawl] Skipping already seen content: {current_url}")
                #     continue
                html_src = self.driver.page_source
                dedup_result = self.content_index.classify(current_url, html_src, driver=self.driver)
                is_new = bool(dedup_result.get("is_new", True))

                if is_new:
                    # Unique page
                    self.unique_page_counter += 1
                    self._save_crawler_screenshot(
                        current_url,
                        is_unique=True,
                        counter=self.unique_page_counter
                    )
                    self.url_to_screenshot_id[current_url] = self.unique_page_counter
                else:
                    # Duplicate page
                    self.duplicate_page_counter += 1
                    cluster_id = dedup_result.get("cluster_id")
                    repr_url = dedup_result.get("repr_url")
                    ref_id = self.url_to_screenshot_id.get(repr_url)

                    self._save_crawler_screenshot(
                        current_url,
                        is_unique=False,
                        counter=self.duplicate_page_counter,
                        ref_id=ref_id
                    )
                    # Duplicate page: skip further processing
                    continue

                # Process new page
                self._navlog(f"[Crawling] Visiting: {current_url}")

                # 2. Collect current page info (excluding task generation)
                self._collect_page_info(current_url)

                # 3. Traverse current page links
                outgoing_links = self.store.get_page(current_url).outgoing_links
                for link in outgoing_links:
                    if self._is_url_blacklisted(link):
                        continue
                    self._add_discovered_links_to_graph(current_url, [link])
                    if link not in visited_urls and link not in nav_queue:
                        nav_queue.append(link)

                # 3.5. If using edge mode, check for new URLs
                if use_edges:
                    new_urls = self._get_new_urls_from_edges(visited_urls, nav_queue)
                    if new_urls:
                        print(f"[Crawl] Discovered {len(new_urls)} new URLs from edges, adding to queue")
                        nav_queue.extend(new_urls)

                # 4. Asynchronously submit LLM task (don't wait for result)
                page = self.store.get_page(current_url)
                title = (self.driver.title or "").strip()
                page.title = title  # Update title

                print(f"[Crawler] Async submitting LLM task: {current_url}")
                future = llm_executor.submit(
                    self._generate_and_save_task,
                    current_url,
                    page,
                    title
                )
                llm_futures.append(future)

                # 5. Update statistics
                self.stats['pages_discovered'] += 1

                # Control pending task count to avoid memory explosion
                if len(llm_futures) >= pending_limit:
                    print(f"[Crawl] Pending LLM tasks reached {len(llm_futures)}, waiting for some to complete...")
                    done, llm_futures = wait(llm_futures, return_when=FIRST_COMPLETED)
                    # Collect results of completed tasks (error handling)
                    for future in done:
                        try:
                            future.result()
                        except Exception as e:
                            print(f"[Crawl] LLM task failed: {e}")
                    llm_futures = list(llm_futures)  # Convert back to list

                # Check stop conditions
                if self.stats['pages_discovered'] >= max_pages:
                    self._navlog(f"Maximum link count reached. Stopping crawl.")
                    break

                if time_limit is not None and (time.time() - start_time) > time_limit:
                    self._navlog(f"Time limit reached. Stopping crawl.")
                    break

            # Wait for all remaining LLM tasks to complete
            if llm_futures:
                print(f"\n[Crawl] Waiting for {len(llm_futures)} LLM tasks to complete...")
                completed_count = 0
                for future in as_completed(llm_futures):
                    completed_count += 1
                    try:
                        future.result(timeout=60)  # Max 60 seconds per task
                        print(f"  [{completed_count}/{len(llm_futures)}] LLM task completed")
                    except TimeoutError:
                        print(f"  [{completed_count}/{len(llm_futures)}] LLM task timed out")
                    except Exception as e:
                        print(f"  [{completed_count}/{len(llm_futures)}] LLM task failed: {e}")
                print(f"[Crawl] All LLM tasks processed\n")

        finally:
            # Ensure thread pool is shut down
            llm_executor.shutdown(wait=False)

        # Output screenshot statistics
        print(f"\n{'='*70}")
        print(f"[Crawl Screenshots Summary]")
        print(f"  Unique pages: {self.unique_page_counter} screenshots saved")
        print(f"     Location: {self.unique_screenshot_dir}")
        print(f"  Duplicate pages: {self.duplicate_page_counter} screenshots saved")
        print(f"     Location: {self.duplicate_screenshot_dir}")
        print(f"  Tip: Use screenshots to debug deduplication logic")
        print(f"{'='*70}\n")

        self._navlog(f"Finished crawling. Total pages discovered: {self.stats['pages_discovered']}")

    def _generate_and_save_task(self, url: str, page: PageInfo, title: str):
        """
        Async execution: generate tasks and save (with retry and error handling)

        Args:
            url: Page URL
            page: PageInfo object
            title: Page title
        """
        max_retries = 3

        for attempt in range(max_retries):
            try:
                # Call LLM to generate tasks
                reasoning, task_descriptions = self.task_gen.generate_logic_for_page(page)

                # Update page info
                page.description = f"Title: {title}\nDescription: {reasoning}"
                page.logic_tasks = task_descriptions

                # Store is thread-safe (locked)
                self.store.add_page(page, persist=True)

                print(f"[Crawler] LLM task completed: {url}")
                print(f"[Crawler] Page description: {page.description}")
                print(f"[Crawler] Page tasks: {task_descriptions}")

                return  # Success, exit

            except Exception as e:
                if attempt < max_retries - 1:
                    # Exponential backoff retry
                    wait_time = 2 ** attempt
                    print(f"[Crawler] LLM task failed (attempt {attempt+1}/{max_retries}), retrying in {wait_time}s: {e}")
                    time.sleep(wait_time)
                    continue
                else:
                    # Last attempt failed, log error but don't raise exception
                    print(f"[Crawler] LLM task ultimately failed: {url} - {e}")
                    # Save an empty task list to avoid incomplete page info
                    page.description = f"Title: {title}\nDescription: [LLM generation failed]"
                    page.logic_tasks = []
                    self.store.add_page(page, persist=True)
                    return

    # Export tasks and semantic graph
    def _get_page_abstract(self, page_url: str) -> str:
        """Get page abstract description (e.g., based on page content)"""
        page_info = self.store.get_page(page_url)
        return page_info.abstract_page

    def _get_page_description(self, page_url: str) -> str:
        """Get page abstract description (e.g., based on page content)"""
        page_info = self.store.get_page(page_url)
        return page_info.description

    def _get_page_logic_tasks(self, page_url: str) -> List[str]:
        """Get generated logical tasks for the page"""
        page = self.store.get_page(page_url)
        return page.logic_tasks if page else []  # Read from page object

    def _filter_valid_nodes_and_edges(self):
        """Filter valid nodes and edges (those that exist in the store)"""
        # Collect valid pages (nodes)
        valid_pages = {url: self.store.get_page(url) for url in self.store.pages if self.store.has_page(url)}

        # Filter edges: only keep edges whose both nodes exist in the store
        valid_edges = [
            edge for edge in self.store.edges
            if edge.from_url in valid_pages and edge.to_url in valid_pages
        ]
        return valid_pages, valid_edges

    def _generate_graph_for_task_plan(self):
        """Generate and return the graph for model, excluding invalid nodes and edges"""
        valid_pages, valid_edges = self._filter_valid_nodes_and_edges()

        # Build all nodes (including nodes without tasks)
        all_nodes = [
            {
                "url": page_url,
                "description": self._get_page_description(page_url),
                "tasks": self._get_page_logic_tasks(page_url)
            }
            for page_url in valid_pages
        ]

        # Filter: only keep nodes with tasks
        # Nodes without tasks are meaningless for task planning and waste LLM tokens
        nodes = [node for node in all_nodes if len(node.get("tasks", [])) > 0]

        # Build valid node URL set (for filtering edges)
        valid_node_urls = {node["url"] for node in nodes}

        # Improvement: aggregate edges into source -> [targets] format
        edge_map = {}  # source -> set of targets
        for edge in valid_edges:
            source = edge.from_url
            target = edge.to_url
            # Only keep edges where both endpoints have tasks
            if source in valid_node_urls and target in valid_node_urls:
                if source not in edge_map:
                    edge_map[source] = set()
                edge_map[source].add(target)

        # Convert to list format
        edges = [
            {
                "source": source,
                "targets": list(targets)
            }
            for source, targets in edge_map.items()
        ]

        graph = {
            "nodes": nodes,
            "edges": edges
        }

        return graph

    def export_task_plan_graph(self, output_path: str = "output/task_plan_graph.json"):
        """Export the graph to a JSON file"""
        graph = self._generate_graph_for_task_plan()

        with open(output_path, 'w', encoding="utf-8") as f:
            json.dump(graph, f, ensure_ascii=False, indent=2)

        print(f"Graph exported successfully to {output_path}")

    # Task execution related
    def run_a_task(self, task, logging_in=False):
        """Execute a task, reusing saved page abstractions"""
        self.tracer.start_task(task.task_id, getattr(task, 'description', ''))

        if self.network_capture:
            self.network_capture.clear_requests()

        self.driver.get(task.initial_url)
        time.sleep(self.settle_wait)

        # Load abstract_page and actions_mapping from cache
        page = self.store.get_page(task.initial_url)
        if page and page.abstract_page:
            self.sensors.abstract_page = page.abstract_page
            print(f"[Crawler] Loaded page abstraction from cache ({len(page.abstract_page)} chars)")

            # Clear and rebuild mapping (restore from saved actions_mapping)
            self.sensors.actions_mapping.clear()
            if page.actions_mapping:
                # Directly restore mapping - pass in complete locators_info dict
                for action_id, locators_info in page.actions_mapping.items():
                    self.sensors.actions_mapping.set_mapping(
                        int(action_id),  # Ensure action_id is integer
                        locators_info  # Pass in complete dict directly
                    )
                print(f"[Crawler] Restored {len(self.sensors.actions_mapping.mapping)} element mappings")
            else:
                print(f"[Crawler] Warning: no actions_mapping in page cache")

            # Clear and rebuild event mapping (fix bug: previously missing, causing TRIGGER command failure)
            self.sensors.event_mapping.clear()
            if page.event_mapping:
                for event_id, event_info in page.event_mapping.items():
                    self.sensors.event_mapping.mapping[int(event_id)] = event_info
                # Update id_counter to max ID + 1
                max_event_id = max(int(k) for k in page.event_mapping.keys())
                self.sensors.event_mapping.id_counter = max_event_id + 1
                print(f"[Crawler] Restored {len(self.sensors.event_mapping.mapping)} event mappings")
            else:
                print(f"[Crawler] Warning: no event_mapping in page cache")
        else:
            # Fallback: rescan
            print(f"[Crawler] Warning: page cache not found, rescanning")
            self.sensors.update_abstract_page()

            # DEBUG: record scan log (write to file)
            if hasattr(self.sensors, 'debug_scan_log'):
                debug_log_path = self.store.traces_dir / f"{task.task_id}" / "scan_debug.log"
                debug_log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(debug_log_path, 'w', encoding='utf-8') as f:
                    f.write("\n".join(self.sensors.debug_scan_log))
                print(f"[Crawler] Scan debug log saved: {debug_log_path}")

        # Execute task
        self.bridge.run_task(task, photo_dir = self.store.traces_dir / f"{task.task_id}", logging_in=logging_in)

        trace = self.tracer.end_task()
        self.store.save_trace(trace)
        print(f"[Crawler] Task {task.task_id} execution completed")

    def _restore_actions_mapping_from_abstract(self):
        """
        Deprecated: no longer parses from abstract_page, now restores directly from PageInfo.actions_mapping
        """
        pass

    # Graph for attack planning agent
    def _generate_execution_graph_with_requests(self, include_trace_requests: bool = True) -> Dict:
        """
        Generate attack planning graph (correct version)

        Args:
            include_trace_requests: Whether to supplement uncovered requests from trace files

        Dedup strategy:
        1. seen_requests: dedup set for this graph generation (avoid intra-graph duplicates)
        2. self.processed_requests: processed set for attack planning (maintained by AttackPlanningAgent)
        3. Initialize seen_requests from processed_requests during graph generation, filtering processed requests
        4. Only dedup in seen_requests, don't modify self.processed_requests
        """
        print(f"\n{'='*60}")
        print(f"[DEBUG] Starting execution graph generation")
        print(f"  store.edges count: {len(self.store.edges)}")
        print(f"  store.pages count: {len(self.store.pages)}")

        # Check if there are edges with search?q=
        search_edges = [e for e in self.store.edges if e.from_url.endswith('#/search') and '?' in e.to_url]
        print(f"  Edges from #/search with params: {len(search_edges)}")
        for e in search_edges:
            print(f"    -> {e.to_url}")
        print(f"{'='*60}\n")

        graph = self._generate_graph_for_task_plan()

        # Rebuild request mapping (refresh each time graph is generated)
        self._build_request_mapping()

        # Correct dedup logic: use local variable seen_requests
        # Initialize from processed_requests, filtering requests already processed by attack planning
        seen_requests = set(self.processed_requests)

        # Statistics
        stats = {
            "total_nodes": 0,
            "nodes_with_requests": 0,
            "total_pending_requests": 0,
            "trace_requests_added": 0  # Count of requests added from traces
        }

        # 1. Add request info for each node
        for node in graph["nodes"]:
            url = node["url"]
            page = self.store.get_page(url)

            # Collect page requests (unprocessed)
            page_requests = []
            if page and page.network_requests:
                for req in page.network_requests:
                    key = self._make_dedup_key(req.method, req.url, req.body)
                    if key not in seen_requests:
                        # Generate ID
                        req_id = self._generate_request_id(key)

                        # Build info with ID
                        request_info = {
                            "id": req_id,  # Inject ID
                            "method": req.method,
                            "url": req.url
                        }
                        if req.method in ["POST", "PUT", "PATCH"] and req.body:
                            request_info["body_schema"] = self._extract_body_schema(req.body)

                        page_requests.append(request_info)
                        seen_requests.add(key)

            # Collect task requests
            tasks_with_requests = []
            for task_desc in node.get("tasks", []):
                task_requests = self._find_task_requests(url, task_desc)

                # Filter processed requests
                unique_task_requests = []
                for req in task_requests:
                    method = req.get("method", "")
                    req_url = req.get("url", "")  # Use req_url to avoid overwriting node URL

                    # Fix: construct fake body from body_schema to generate correct key
                    body_schema = req.get("body_schema")
                    if body_schema and method.upper() in ["POST", "PUT", "PATCH"]:
                        # Construct fake body from body_schema
                        keys = [k.strip() for k in body_schema.split(',')]
                        fake_body = json.dumps({k: "" for k in keys}, sort_keys=True)
                        key = self._make_dedup_key(method, req_url, fake_body)
                    else:
                        key = self._make_dedup_key(method, req_url, None)

                    if key not in seen_requests:
                        # Inject ID
                        req_copy = dict(req) # Copy to avoid modifying original data
                        req_copy["id"] = self._generate_request_id(key) # Inject ID

                        unique_task_requests.append(req_copy)
                        seen_requests.add(key)

                # Only add tasks with unprocessed requests
                if unique_task_requests:
                    tasks_with_requests.append({
                        "description": task_desc,
                        "requests": unique_task_requests
                    })

            # Collect outgoing link requests
            outgoing_request_links = []

            # 1. If the node URL itself has params, add it as a GET request
            # This allows attack planning to analyze URL params (e.g. #/search?q=xxx)
            node_url = node["url"]
            if '?' in node_url:
                key = self._make_dedup_key("GET", node_url, None)
                if key not in seen_requests:
                    outgoing_request_links.append({"method": "GET", "url": node_url})
                    seen_requests.add(key)

            # 2. Collect static links from page.outgoing_links
            if page and page.outgoing_links:
                for link in page.outgoing_links:
                    # Filter: URLs with # (fragment) are not sent to server, skip
                    if '#' in link:
                        continue

                    key = self._make_dedup_key("GET", link, None)
                    if key not in seen_requests:
                        req_id = self._generate_request_id(key) # Generate ID

                        # [Fix] Immediately register to global ID mapping table
                        # Build a standard request object structure
                        # Note: this is a static link, treated as GET request, no body
                        if req_id not in self.request_id_map:
                            self.request_id_map[req_id] = {
                                "method": "GET",
                                "url": link,
                                "headers": {},
                                "body": None,
                                "response_status": None,
                                "response_body": None,
                                "note": "Generated from page.outgoing_links"
                            }

                        outgoing_request_links.append({
                            "id": req_id,
                            "method": "GET",
                            "url": link
                        })
                        seen_requests.add(key)

            # 3. Supplement dynamic jumps from store.edges (including all dynamically generated URLs)
            # Debug: count edges from current node
            edges_from_current = [e for e in self.store.edges if e.from_url == url]
            edges_with_params = [e for e in edges_from_current if '?' in e.to_url]

            if url == "http://127.0.0.1:4281/#/search":
                print(f"\n[DEBUG] Processing node: {url}")
                print(f"  Total edges in store: {len(self.store.edges)}")
                print(f"  Edges from this node: {len(edges_from_current)}")
                print(f"  Edges with params: {len(edges_with_params)}")
                for e in edges_with_params:
                    print(f"    -> {e.to_url}")

            for edge in self.store.edges:
                if edge.from_url == url:  # Find edges from current node
                    to_url = edge.to_url

                    # ========== Filter logic adjustment ==========
                    # Old logic (commented out): only process URLs with params
                    # Reason: URLs with params (e.g. #/page?id=1) are more likely to have injection points
                    # if '?' in to_url:
                    #
                    # New logic: keep all dynamic jump URLs (including those without params)
                    # Reason: URLs without params may also have logic vulnerabilities (e.g. IDOR, unauthorized access, etc.)
                    # E.g.: POST /api/user/delete, GET /admin/panel, etc.
                    # ========================================

                    key = self._make_dedup_key("GET", to_url, None)
                    if key not in seen_requests:
                        req_id = self._generate_request_id(key) # Generate ID

                        # [Fix] Immediately register to global ID mapping table
                        if req_id not in self.request_id_map:
                            self.request_id_map[req_id] = {
                                "method": "GET",
                                "url": to_url,
                                "headers": {},
                                "body": None,
                                "response_status": None,
                                "response_body": None,
                                "note": "Generated from store.edges"
                            }

                        outgoing_request_links.append({
                            "id": req_id,
                            "method": "GET",
                            "url": to_url
                        })
                        seen_requests.add(key)

            # Update node info
            node["page_requests"] = page_requests
            node["tasks"] = tasks_with_requests
            node["outgoing_links"] = outgoing_request_links

            # Statistics
            node_total = len(page_requests) + len(outgoing_request_links)
            for task in tasks_with_requests:
                node_total += len(task["requests"])

            if node_total > 0:
                stats["nodes_with_requests"] += 1
                stats["total_pending_requests"] += node_total

        # 2. If enabled, supplement requests from trace files
        if include_trace_requests:
            orphan_requests = self._extract_orphan_requests_from_traces(seen_requests)
            self._integrate_orphan_requests(graph, orphan_requests, stats)

        # 3. Filter nodes: keep those with unprocessed requests
        filtered_nodes = []
        valid_urls = set()

        for node in graph["nodes"]:
            has_pending = (
                len(node.get("page_requests", [])) > 0 or
                len(node.get("tasks", [])) > 0 or
                len(node.get("outgoing_links", [])) > 0 or
                len(node.get("trace_requests", [])) > 0 or  # trace requests
                len(node.get("pre_navigation_requests", [])) > 0  # pre_navigation requests
            )

            if has_pending:
                filtered_nodes.append(node)
                valid_urls.add(node["url"])

        stats["total_nodes"] = len(filtered_nodes)

        # 4. Filter edges: only keep connections between valid nodes
        filtered_edges = []
        for edge in graph.get("edges", []):
            source = edge["source"]
            targets = [t for t in edge.get("targets", []) if t in valid_urls]
            if source in valid_urls and targets:
                filtered_edges.append({
                    "source": source,
                    "targets": targets
                })

        final_graph = {
            "nodes": filtered_nodes,
            # "edges": filtered_edges
        }

        # Print statistics (not included in returned graph)
        print(f"[Graph Stats] Nodes: {stats['total_nodes']}, "
            f"Nodes with requests: {stats['nodes_with_requests']}, "
            f"Total pending requests: {stats['total_pending_requests']}")
        if include_trace_requests:
            print(f"[Graph Stats] Trace requests added: {stats['trace_requests_added']}")

        return final_graph



    def export_execution_graph_with_requests(self, output_path: str = "output/execution_graph_with_requests.json", include_trace_requests: bool = False):
        """
        Export attack planning graph to file (fixed version)

        Args:
            output_path: Export file path
            include_trace_requests: Whether to supplement uncovered requests from trace files (default False)

        Improvements:
        - Added state snapshot at export time
        - Support for supplementing pre-execution task requests from trace files (e.g. login)
        """
        # Generate graph
        final_graph = self._generate_execution_graph_with_requests(include_trace_requests=include_trace_requests)

        # Add export timestamp (for debugging)
        import time
        final_graph["exported_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
        final_graph["total_processed"] = len(self.processed_requests)
        final_graph["include_trace_requests"] = include_trace_requests

        # Export to file
        with open(output_path, 'w', encoding="utf-8") as f:
            json.dump(final_graph, f, ensure_ascii=False, indent=2)

        # Print summary
        node_count = len(final_graph['nodes'])

        print(f"Attack planning graph exported: {output_path}")
        print(f"  - Node count: {node_count}")
        print(f"  - Processed requests: {len(self.processed_requests)}")
        if include_trace_requests:
            print(f"  - Includes trace requests: yes")

        # If graph is empty, give warning
        if node_count == 0:
            print("  Warning: Graph is empty! All requests may have been marked as processed")
            print(f"     - Check processed_requests: {len(self.processed_requests)} items")
            print(f"     - Check request_mapping: {len(self.request_mapping)} items")

        return final_graph


    def _find_task_requests(self, page_url: str, task_desc: str) -> List[Dict]:
        """
        Find network requests produced during task execution based on page URL and task description

        Args:
            page_url: Page URL
            task_desc: Task description

        Returns:
            List of network requests produced during task execution
        """
        try:
            # Iterate through all trace files
            for trace_file in self.store.traces_dir.glob("task_*.json"):
                try:
                    trace_data = json.loads(trace_file.read_text(encoding="utf-8"))

                    # Check if this trace's task description matches
                    trace_task_desc = trace_data.get("description", "")
                    # Use similarity matching (allow some differences)
                    if self._is_task_match(task_desc, trace_task_desc):
                        # Extract network requests from all steps of this task
                        all_requests = []

                        for step in trace_data.get("steps", []):
                            step_requests = step.get("network_requests", [])
                            for req in step_requests:
                                # Fix: add body_schema for POST requests instead of full body
                                request_info = {
                                    "method": req.get("method", ""),
                                    "url": req.get("url", "")
                                }
                                method = req.get("method", "")
                                body = req.get("body")
                                if method in ["POST", "PUT", "PATCH"] and body:
                                    # Extract body_schema
                                    body_schema = self._extract_body_schema(body)
                                    request_info["body_schema"] = body_schema
                                all_requests.append(request_info)

                        # Deduplicate (preserve order)
                        seen = set()
                        unique_requests = []
                        for req in all_requests:
                            req_key = f"{req['method']}:{req['url']}"
                            if req_key not in seen:
                                seen.add(req_key)
                                unique_requests.append(req)

                        if unique_requests:
                            return unique_requests

                except Exception as e:
                    print(f"[Warning] Failed to parse trace file {trace_file}: {e}")
                    continue

            return []

        except Exception as e:
            print(f"[Error] Failed to find task requests: {e}")
            return []


    def _extract_orphan_requests_from_traces(self, seen_requests: set) -> List[Dict]:
        """
        Extract requests from trace files not covered by the graph (orphan requests)

        Args:
            seen_requests: Set of requests already in the graph

        Returns:
            List of orphan requests, each element contains:
            {
                "request": {...},      # request object
                "from_url": "...",     # triggering page URL
                "to_url": "...",       # jump target URL
                "task_desc": "..."     # task description
            }
        """
        orphan_requests = []

        try:
            for trace_file in self.store.traces_dir.glob("task_*.json"):
                try:
                    trace_data = json.loads(trace_file.read_text(encoding="utf-8"))

                    for step in trace_data.get("steps", []):
                        from_url = step.get("from_url")
                        to_url = step.get("to_url")

                        for req in step.get("network_requests", []):
                            method = req.get("method", "")
                            url = req.get("url", "")
                            key = self._make_dedup_key(method, url, req.get("body"))

                            # Only extract requests not in the graph
                            if key not in seen_requests:
                                # Fix: add body_schema for POST requests instead of full body
                                req_id = self._generate_request_id(key) # Generate ID

                                # [Fix 3] Defensive registration: in case _build_request_mapping missed it, register here
                                if req_id not in self.request_id_map:
                                    # req from trace is complete raw data, store directly
                                    self.request_id_map[req_id] = req

                                request_info = {
                                    "id": req_id, # Inject ID
                                    "method": method,
                                    "url": url
                                }
                                body = req.get("body")
                                if method in ["POST", "PUT", "PATCH"] and body:
                                    # Extract body_schema
                                    body_schema = self._extract_body_schema(body)
                                    request_info["body_schema"] = body_schema

                                orphan_requests.append({
                                    "request": request_info,
                                    "from_url": from_url,
                                    "to_url": to_url,
                                    "task_desc": trace_data.get("description", "")
                                })

                                # Add to seen_requests to avoid duplicates
                                seen_requests.add(key)

                except Exception as e:
                    print(f"[Warning] Failed to parse trace file {trace_file}: {e}")
                    continue

        except Exception as e:
            print(f"[Error] Failed to extract orphan requests: {e}")

        print(f"[Trace] Extracted {len(orphan_requests)} orphan requests from trace files")
        return orphan_requests

    def _integrate_orphan_requests(self, graph: Dict, orphan_requests: List[Dict], stats: Dict):
        """
        Integrate orphan requests into the graph

        Strategy:
        1. Preferentially associate to from_url node (trace_requests field)
        2. If from_url doesn't exist, associate to to_url node (pre_navigation_requests field)
        3. If neither exists, create a temporary node

        Args:
            graph: Graph object (will be modified)
            orphan_requests: List of orphan requests
            stats: Statistics (will be updated)
        """
        if not orphan_requests:
            return

        url_to_node = {node["url"]: node for node in graph["nodes"]}
        temp_nodes = {}

        for item in orphan_requests:
            req = item["request"]
            from_url = item["from_url"]
            to_url = item["to_url"]
            task_desc = item["task_desc"]

            # Strategy 1: add to from_url node's trace_requests
            if from_url in url_to_node:
                if "trace_requests" not in url_to_node[from_url]:
                    url_to_node[from_url]["trace_requests"] = []
                url_to_node[from_url]["trace_requests"].append(req)
                stats["trace_requests_added"] += 1
                continue

            # Strategy 2: add to to_url node's pre_navigation_requests
            # Semantics: these requests were triggered before navigating to this page (e.g. login request associated with homepage)
            if to_url and to_url in url_to_node:
                if "pre_navigation_requests" not in url_to_node[to_url]:
                    url_to_node[to_url]["pre_navigation_requests"] = []
                url_to_node[to_url]["pre_navigation_requests"].append(req)
                stats["trace_requests_added"] += 1
                continue

            # Strategy 3: create temporary node
            if from_url not in temp_nodes:
                temp_nodes[from_url] = {
                    "url": from_url,
                    "description": f"[Execution-only] {task_desc[:100]}",
                    "tasks": [],
                    "page_requests": [],
                    "outgoing_links": [],
                    "trace_requests": [],
                    "is_temporary": True  # Mark as temporary node
                }
            temp_nodes[from_url]["trace_requests"].append(req)
            stats["trace_requests_added"] += 1

        # Add temporary nodes to graph
        if temp_nodes:
            graph["nodes"].extend(temp_nodes.values())
            print(f"[Trace] Created {len(temp_nodes)} temporary nodes for orphan requests")

    def _is_task_match(self, task_desc1: str, task_desc2: str) -> bool:
        """
        Determine if two task descriptions match (exact match)
        """
        if not task_desc1 or not task_desc2:
            return False

        # Normalize: lowercase, remove extra whitespace
        desc1 = task_desc1.lower().strip()
        desc2 = task_desc2.lower().strip()

        # Exact equality
        return desc1 == desc2
