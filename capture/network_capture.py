# -*- coding: utf-8 -*-
# crawl/network_capture.py
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import json

class NetworkCapture:
    """selenium-wire network request capture and processing tool"""

    # Static resource extensions
    STATIC_EXTENSIONS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico',
        '.woff', '.woff2', '.ttf', '.svg', '.webp', '.map',
        '.eot', '.otf', '.mp4', '.mp3', '.avi', '.mov'
    }

    # Ignored domain patterns
    IGNORED_DOMAINS = {
        'google-analytics.com', 'googletagmanager.com', 'facebook.com',
        'doubleclick.net', 'twitter.com', 'linkedin.com', 'cloudflare.com',
        'googleapis.com', 'gstatic.com', 'cdnjs.cloudflare.com'
    }

    def __init__(self, driver):
        """
        :param driver: selenium-wire webdriver instance
        """
        self.driver = driver
        self.captured_requests = []

    def clear_requests(self):
        """Clear the driver's request records"""
        if hasattr(self.driver, 'requests'):
            del self.driver.requests
        self.captured_requests.clear()

    def capture_current(self,
                       current_url: str,
                       exclude_static: bool = True,
                       exclude_main_doc: bool = False,
                       max_body_size: int = 10**12) -> List[Dict[str, Any]]:
        """
        Capture all current network requests

        :param current_url: Current page URL, used to filter main document requests
        :param exclude_static: Whether to exclude static resources
        :param exclude_main_doc: Whether to exclude main document requests
        :param max_body_size: Maximum response body recording size
        :return: Formatted request list
        """
        if not hasattr(self.driver, 'requests'):
            return []

        captured = []
        current_domain = urlparse(current_url).netloc

        for request in self.driver.requests:
            # Filter conditions
            if self._should_skip_request(request, current_url, current_domain,
                                        exclude_static, exclude_main_doc):
                continue

            # Format request
            formatted = self._format_request(request, max_body_size)
            if formatted:
                captured.append(formatted)

        self.captured_requests = captured
        return captured

    def _should_skip_request(self, request, current_url: str, current_domain: str,
                           exclude_static: bool, exclude_main_doc: bool) -> bool:
        """Determine whether this request should be skipped"""
        try:
            url = request.url
            parsed = urlparse(url)

            # # Exclude main document
            # if exclude_main_doc and url == current_url:
            #     return True

            # Exclude static resources
            if exclude_static:
                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
                    return True

            # Exclude third-party analytics/tracking domains
            if any(domain in parsed.netloc for domain in self.IGNORED_DOMAINS):
                return True

            # Optional: only keep same-origin requests
            if parsed.netloc != current_domain:
                return True

            return False

        except Exception:
            return True

    def _format_request(self, request, max_body_size: int) -> Optional[Dict[str, Any]]:
        """Format a single request"""
        try:
            # Parse query parameters
            parsed = urlparse(request.url)
            query_params = {}
            if parsed.query:
                qs = parse_qs(parsed.query)
                # Simplify: flatten single-value parameters
                query_params = {k: (v[0] if len(v) == 1 else v) for k, v in qs.items()}

            # Process request headers
            req_headers = {}
            for k, v in (request.headers or {}).items():
                if isinstance(v, bytes):
                    v = v.decode('utf-8', errors='replace')
                # # Filter sensitive headers
                # if k.lower() not in ['cookie', 'authorization']:
                #     req_headers[k] = str(v)
                req_headers[k] = str(v)

            # Process request body
            req_body = None
            if request.body:
                req_body = self._decode_body(request.body, max_body_size)

            # Process response
            response_data = {}
            if hasattr(request, 'response') and request.response:
                resp = request.response
                response_data = {
                    'status': resp.status_code,
                    'headers': {},
                    'body': None
                }

                # Response headers
                for k, v in (resp.headers or {}).items():
                    # if k.lower() not in ['set-cookie']:
                        response_data['headers'][k] = str(v)

                # Response body (only record JSON/HTML/XML)
                content_type = resp.headers.get('Content-Type', '').lower()
                if any(ct in content_type for ct in ['json', 'html', 'xml', 'text']):
                    response_data['body'] = self._decode_body(resp.body, max_body_size)

            # Calculate duration
            duration = None
            if hasattr(request, 'date') and hasattr(request.response, 'date'):
                duration = (request.response.date - request.date).total_seconds() * 1000

            return {
                'method': request.method,
                'url': request.url,
                'path': parsed.path,
                'query_params': query_params,
                'headers': req_headers,
                'body': req_body,
                'response': response_data,
                'duration_ms': duration,
                'timestamp': datetime.utcnow().isoformat()
            }

        except Exception as e:
            print(f"Failed to format request {request.url}: {e}")
            return None

    def _decode_body(self, body, max_size: int) -> Optional[str]:
        """Decode request/response body (supports gzip/deflate decompression)"""
        if not body:
            return None

        try:
            if isinstance(body, bytes):
                # Detect and decompress gzip/deflate encoding
                original_body = body

                # Detect gzip magic bytes (0x1f 0x8b)
                if len(body) >= 2 and body[0] == 0x1f and body[1] == 0x8b:
                    try:
                        import gzip
                        body = gzip.decompress(body)
                    except Exception as e:
                        # gzip decompression failed, use original data
                        print(f"[NetworkCapture] gzip decompress failed: {e}")
                        body = original_body

                # Detect deflate/zlib magic bytes (0x78)
                elif len(body) >= 2 and body[0] == 0x78 and body[1] in (0x01, 0x5e, 0x9c, 0xda):
                    try:
                        import zlib
                        body = zlib.decompress(body)
                    except Exception as e:
                        # deflate decompression failed, use original data
                        print(f"[NetworkCapture] zlib decompress failed: {e}")
                        body = original_body

                # Limit size
                if len(body) > max_size:
                    body = body[:max_size]
                    truncated = True
                else:
                    truncated = False

                # Try decoding
                try:
                    text = body.decode('utf-8')
                except UnicodeDecodeError:
                    text = body.decode('latin-1', errors='replace')

                if truncated:
                    text += f"\n... [truncated {len(body) - max_size} bytes]"

                return text
            else:
                text = str(body)
                if len(text) > max_size:
                    return text[:max_size] + "... [truncated]"
                return text

        except Exception:
            return f"<{len(body)} bytes, decode failed>"

    def get_api_requests_only(self) -> List[Dict[str, Any]]:
        """Return only API requests (non-static resources)"""
        return [req for req in self.captured_requests
                if self._is_api_request(req['url'])]

    def _is_api_request(self, url: str) -> bool:
        """Determine if this is an API request"""
        path = urlparse(url).path.lower()
        return not any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)

    def export_to_har(self, page_title: str = "Captured Page") -> Dict[str, Any]:
        """Export to HAR format (can be imported in Chrome DevTools)"""
        # Simplified HAR format implementation
        entries = []
        for req in self.captured_requests:
            entry = {
                "startedDateTime": req.get('timestamp', ''),
                "time": req.get('duration_ms', 0),
                "request": {
                    "method": req['method'],
                    "url": req['url'],
                    "headers": [{"name": k, "value": v} for k, v in req.get('headers', {}).items()],
                    "queryString": [{"name": k, "value": str(v)} for k, v in req.get('query_params', {}).items()],
                    "postData": {"text": req.get('body', '')} if req.get('body') else {}
                },
                "response": {
                    "status": req.get('response', {}).get('status', 0),
                    "headers": [{"name": k, "value": v}
                               for k, v in req.get('response', {}).get('headers', {}).items()],
                    "content": {
                        "text": req.get('response', {}).get('body', ''),
                        "mimeType": req.get('response', {}).get('headers', {}).get('Content-Type', '')
                    }
                }
            }
            entries.append(entry)

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "WebCrawler", "version": "1.0"},
                "pages": [{"title": page_title, "id": "page_1"}],
                "entries": entries
            }
        }
