# -*- coding: utf-8 -*-
# crawl/network_capture.py
from typing import List, Optional, Dict, Any, Set
from urllib.parse import urlparse, parse_qs
from datetime import datetime
import json

class NetworkCapture:
    """selenium-wire 网络请求捕获和处理工具"""
    
    # 静态资源扩展名
    STATIC_EXTENSIONS = {
        '.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.ico',
        '.woff', '.woff2', '.ttf', '.svg', '.webp', '.map',
        '.eot', '.otf', '.mp4', '.mp3', '.avi', '.mov'
    }
    
    # 忽略的域名模式
    IGNORED_DOMAINS = {
        'google-analytics.com', 'googletagmanager.com', 'facebook.com',
        'doubleclick.net', 'twitter.com', 'linkedin.com', 'cloudflare.com',
        'googleapis.com', 'gstatic.com', 'cdnjs.cloudflare.com'
    }
    
    def __init__(self, driver):
        """
        :param driver: selenium-wire 的 webdriver 实例
        """
        self.driver = driver
        self.captured_requests = []
    
    def clear_requests(self):
        """清空driver的请求记录"""
        if hasattr(self.driver, 'requests'):
            del self.driver.requests
        self.captured_requests.clear()
    
    def capture_current(self, 
                       current_url: str,
                       exclude_static: bool = True,
                       exclude_main_doc: bool = False,
                       max_body_size: int = 10**12) -> List[Dict[str, Any]]:
        """
        捕获当前的所有网络请求
        
        :param current_url: 当前页面URL，用于过滤主文档请求
        :param exclude_static: 是否排除静态资源
        :param exclude_main_doc: 是否排除主文档请求
        :param max_body_size: 响应体最大记录大小
        :return: 格式化的请求列表
        """
        if not hasattr(self.driver, 'requests'):
            return []
        
        captured = []
        current_domain = urlparse(current_url).netloc
        
        for request in self.driver.requests:
            # 过滤条件
            if self._should_skip_request(request, current_url, current_domain, 
                                        exclude_static, exclude_main_doc):
                continue
            
            # 格式化请求
            formatted = self._format_request(request, max_body_size)
            if formatted:
                captured.append(formatted)
        
        self.captured_requests = captured
        return captured
    
    def _should_skip_request(self, request, current_url: str, current_domain: str,
                           exclude_static: bool, exclude_main_doc: bool) -> bool:
        """判断是否应该跳过该请求"""
        try:
            url = request.url
            parsed = urlparse(url)
            
            # # 排除主文档
            # if exclude_main_doc and url == current_url:
            #     return True
            
            # 排除静态资源
            if exclude_static:
                path_lower = parsed.path.lower()
                if any(path_lower.endswith(ext) for ext in self.STATIC_EXTENSIONS):
                    return True
            
            # 排除第三方分析/追踪域名
            if any(domain in parsed.netloc for domain in self.IGNORED_DOMAINS):
                return True
            
            # 可选：只保留同源请求
            if parsed.netloc != current_domain:
                return True
            
            return False
            
        except Exception:
            return True
    
    def _format_request(self, request, max_body_size: int) -> Optional[Dict[str, Any]]:
        """格式化单个请求"""
        try:
            # 解析查询参数
            parsed = urlparse(request.url)
            query_params = {}
            if parsed.query:
                qs = parse_qs(parsed.query)
                # 简化：单值参数展平
                query_params = {k: (v[0] if len(v) == 1 else v) for k, v in qs.items()}
            
            # 处理请求头
            req_headers = {}
            for k, v in (request.headers or {}).items():
                if isinstance(v, bytes):
                    v = v.decode('utf-8', errors='replace')
                # # 过滤敏感头部
                # if k.lower() not in ['cookie', 'authorization']:
                #     req_headers[k] = str(v)
                req_headers[k] = str(v)
            
            # 处理请求体
            req_body = None
            if request.body:
                req_body = self._decode_body(request.body, max_body_size)
            
            # 处理响应
            response_data = {}
            if hasattr(request, 'response') and request.response:
                resp = request.response
                response_data = {
                    'status': resp.status_code,
                    'headers': {},
                    'body': None
                }
                
                # 响应头
                for k, v in (resp.headers or {}).items():
                    # if k.lower() not in ['set-cookie']:
                        response_data['headers'][k] = str(v)
                
                # 响应体（只记录JSON/HTML/XML）
                content_type = resp.headers.get('Content-Type', '').lower()
                if any(ct in content_type for ct in ['json', 'html', 'xml', 'text']):
                    response_data['body'] = self._decode_body(resp.body, max_body_size)
            
            # 计算耗时
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
            print(f"格式化请求失败 {request.url}: {e}")
            return None
    
    def _decode_body(self, body, max_size: int) -> Optional[str]:
        """解码请求/响应体（支持gzip/deflate解压）"""
        if not body:
            return None

        try:
            if isinstance(body, bytes):
                # ✅ 检测并解压 gzip/deflate 编码
                original_body = body

                # 检测 gzip 魔术字节 (0x1f 0x8b)
                if len(body) >= 2 and body[0] == 0x1f and body[1] == 0x8b:
                    try:
                        import gzip
                        body = gzip.decompress(body)
                    except Exception as e:
                        # gzip解压失败，使用原始数据
                        print(f"[NetworkCapture] gzip decompress failed: {e}")
                        body = original_body

                # 检测 deflate/zlib 魔术字节 (0x78)
                elif len(body) >= 2 and body[0] == 0x78 and body[1] in (0x01, 0x5e, 0x9c, 0xda):
                    try:
                        import zlib
                        body = zlib.decompress(body)
                    except Exception as e:
                        # deflate解压失败，使用原始数据
                        print(f"[NetworkCapture] zlib decompress failed: {e}")
                        body = original_body

                # 限制大小
                if len(body) > max_size:
                    body = body[:max_size]
                    truncated = True
                else:
                    truncated = False

                # 尝试解码
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
        """只返回API请求（非静态资源）"""
        return [req for req in self.captured_requests 
                if self._is_api_request(req['url'])]
    
    def _is_api_request(self, url: str) -> bool:
        """判断是否为API请求"""
        path = urlparse(url).path.lower()
        return not any(path.endswith(ext) for ext in self.STATIC_EXTENSIONS)
    
    def export_to_har(self, page_title: str = "Captured Page") -> Dict[str, Any]:
        """导出为HAR格式（可用于Chrome DevTools导入）"""
        # HAR格式的简化实现
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