import os
import json
import requests
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
import re
from queue import Queue
from threading import Lock
class Scanner:
    def __init__(self, shell, depth, os, threads, filename, scan_settings):
        self.shell = shell
        self.depth = int(depth)
        self.target_os = os.lower()  # 'windows' или 'linux'
        self.threads = int(threads)
        self.scan_settings = scan_settings
        self.session = requests.Session()
        self.results = {
            'metadata': {
                'start_time': datetime.now().isoformat(),
                'target_os': self.target_os,
                'scan_settings': scan_settings.__getstate__()
            },
            'vulnerabilities': []
        }
        self.results_file = "Results/"+filename
        self.payloads = self._load_os_specific_payloads()


#region Работа с полезными нагрузками

    def _load_os_specific_payloads(self):
        # Загружает и санитизирует payloads из файла с учетом глубины сканирования
        payload_file = "Wordlists/Tests.txt"
        if self.target_os=="linux":
            payload_file="Wordlists/ForLinux.txt"
        else:
            payload_file="Wordlists/ForWindows"

        if not os.path.exists(payload_file):
            raise FileNotFoundError(f"Payload file {payload_file} not found!")

        payloads = []
        with open(payload_file, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                sanitized = re.sub(r'[\x00-\x1F\x7F]', '', line).strip()
                if sanitized:
                    payloads.append(sanitized)

        if not hasattr(self, 'depth') or self.depth not in range(1, 7):
            self.depth = 6
        if self.depth == 6:
            return payloads
        else:
            chunk_size = len(payloads) // 6
            return payloads[:chunk_size * self.depth]

    def _sanitize_payload(self, payload):
        # Удаляем управляющие символы, но не экранируем для URL
        return re.sub(r'[\x00-\x1F\x7F]', '', payload).strip()

#endregion

#region Основной метод сканирования
    def StartScan(self):
        # Универсальный метод для сканирования всех возможных векторов атаки
        vectors = self._identify_attack_vectors()
        print(f"Сканирование {self.scan_settings.scanname} запущено")

        if not vectors:
            raise ValueError("No attack vectors found (no '*' markers)")

        print(f"[*] Starting scan with {len(vectors)} attack vectors...")

        results = []
        for vector_type, vector_data in vectors.items():
            print(f"[*] Scanning {vector_type} vector...")
            result = self._scan_vector(vector_type, vector_data)
            if result:
                results.append(result)

        self._save_results()
        return {
            'status': 'completed',
            'vulnerabilities_found': len(self.results['vulnerabilities']),
            'results_file': os.path.abspath(self.results_file),
            'scanned_vectors': [v for v in vectors.keys()]
        }
#endregion

#region Вспомогательные методы
    def _identify_attack_vectors(self):
        #Идентифицирует все возможные векторы атаки
        vectors = {}

        # URL
        if '*' in self.scan_settings.url:
            parts = self.scan_settings.url.split('*')
            if len(parts) == 2:
                vectors['url'] = {
                    'base_parts': parts,
                    'original': self.scan_settings.url
                }

        # Тело запроса (для POST, PUT)
        print(self.scan_settings.rbody)
        method = self.scan_settings.method.upper()
        if method in ['POST', 'PUT', 'PATCH'] and self.scan_settings.rbody and '*' in self.scan_settings.rbody:
            print(self.scan_settings.rbody)
            vectors['request_body'] = {
                'template': self.scan_settings.rbody,
                'original': self.scan_settings.rbody
            }

        # Заголовки
        for header, value in self.scan_settings.headers.items():
            if '*' in value:
                if 'headers' not in vectors:
                    vectors['headers'] = {}
                vectors['headers'][header] = {
                    'template': value,
                    'original': value
                }

        # Cookies
        for cookie, value in self.scan_settings.cookies.items():
            if '*' in value:
                if 'cookies' not in vectors:
                    vectors['cookies'] = {}
                vectors['cookies'][cookie] = {
                    'template': value,
                    'original': value
                }

        return vectors
    def _detect_vulnerability(self, response, payload):
        #Определяет наличие уязвимости по ответу сервера
        if not response:
            return False, None

        indicators = {
            'linux': ['root:', '/etc/passwd', 'bin/bash'],
            'windows': ['[boot loader]', 'Program Files', 'Windows NT']
        }

        if response.status_code == 200:
            if any(indicator in response.text
                   for indicator in indicators.get(self.target_os, [])):
                return True, {
                    'status_code': response.status_code,
                    'response_length': len(response.text),
                    'content_match': True
                }
            return True, {
                'status_code': response.status_code,
                'response_length': len(response.text),
                'content_match': False
            }
        return False, None

    def _send_request(self, url=None, headers=None, cookies=None, data=None):
        #Отправляет HTTP запрос с учетом метода
        try:
            method = self.scan_settings.method.upper()
            send_data = None

            # Для методов, поддерживающих тело запроса
            if method in ['POST', 'PUT', 'PATCH']:
                send_data = data or self.scan_settings.rbody
            elif method == 'GET' and data:
                # Для GET добавляем данные как query параметры
                url = url or self.scan_settings.url
                parsed = urllib.parse.urlparse(url)
                query = urllib.parse.parse_qsl(parsed.query)
                query.extend(urllib.parse.parse_qsl(data))
                new_query = urllib.parse.urlencode(query)
                url = urllib.parse.urlunparse(parsed._replace(query=new_query))

            return self.session.request(
                method=method,
                url=url or self.scan_settings.url,
                headers=headers or self.scan_settings.headers,
                cookies=cookies or self.scan_settings.cookies,
                data=send_data,
                timeout=10,
                allow_redirects=False
            )
        except requests.RequestException as e:
            print(f"[!] Request failed: {e}")
            return None
#endregion

#region Сканирование векторов
    def _scan_vector(self, vector_type, vector_data):
        #Сканирует конкретный вектор атаки
        if vector_type == 'url':
            return self._scan_url_vector(vector_data)
        elif vector_type == 'request_body':
            return self._scan_request_body_vector(vector_data)
        elif vector_type == 'headers':
            return self._scan_headers_vector(vector_data)
        elif vector_type == 'cookies':
            return self._scan_cookies_vector(vector_data)
        else:
            print(f"[!] Unknown vector type: {vector_type}")
            return None

    def _scan_url_vector(self, vector_data):
        """Сканирует URL вектор с поочередным распределением payloads по потокам"""
        from queue import Queue
        from threading import Lock

        # Создаем очередь payloads для потокобезопасного доступа
        payloads_queue = Queue()
        for payload in self.payloads:
            payloads_queue.put(payload)

        # Объект блокировки для безопасного доступа к результатам
        results_lock = Lock()

        def worker():
            while not payloads_queue.empty():
                try:
                    payload = payloads_queue.get()
                    result = self._test_url_payload(vector_data['base_parts'], payload)
                    if result:
                        with results_lock:
                            self.results['vulnerabilities'].append(result)
                except Exception as e:
                    print(f"[!] Error testing URL payload {payload}: {e}")
                finally:
                    payloads_queue.task_done()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Запускаем потоки, каждый будет брать следующий payload из очереди
            for _ in range(self.threads):
                executor.submit(worker)

            # Ждем завершения всех задач в очереди
            payloads_queue.join()

        return {
            'vector_type': 'url',
            'vulnerabilities_found': sum(1 for v in self.results['vulnerabilities']
                                         if v['type'] == 'url_traversal')
        }

    def _scan_request_body_vector(self, vector_data):
        #Сканирует тело запроса (POST, PUT) с поочередным распределением payloads
        method = self.scan_settings.method.upper()



        payloads_queue = Queue()
        for payload in self.payloads:
            payloads_queue.put(payload)

        results_lock = Lock()

        def worker():
            while not payloads_queue.empty():
                try:
                    payload = payloads_queue.get()
                    result = self._test_request_body_payload(vector_data['template'], payload)
                    if result:
                        with results_lock:
                            self.results['vulnerabilities'].append(result)
                except Exception as e:
                    print(f"[!] Error testing {method} payload {payload}: {e}")
                finally:
                    payloads_queue.task_done()

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            for _ in range(self.threads):
                executor.submit(worker)
            payloads_queue.join()

        return {
            'vector_type': 'request_body',
            'method': method,
            'vulnerabilities_found': sum(
                1 for v in self.results['vulnerabilities'] if v['type'] == f'{method.lower()}_traversal')
        }

    def _scan_headers_vector(self, headers_data):
        #Сканирует заголовки с поочередным распределением payloads
        from queue import Queue
        from threading import Lock
        results = []

        for header_name, header_info in headers_data.items():
            print(f"[*] Scanning header: {header_name}")

            payloads_queue = Queue()
            for payload in self.payloads:
                payloads_queue.put(payload)

            results_lock = Lock()

            def worker(header_name, header_template):
                while not payloads_queue.empty():
                    try:
                        payload = payloads_queue.get()
                        result = self._test_header_payload(header_name, header_template, payload)
                        if result:
                            with results_lock:
                                self.results['vulnerabilities'].append(result)
                                results.append(result)
                    except Exception as e:
                        print(f"[!] Error testing header payload {payload}: {e}")
                    finally:
                        payloads_queue.task_done()

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for _ in range(self.threads):
                    executor.submit(worker, header_name, header_info['template'])
                payloads_queue.join()

        return {
            'vector_type': 'headers',
            'vulnerabilities_found': len(results),
            'scanned_headers': list(headers_data.keys())
        }

    def _scan_cookies_vector(self, cookies_data):
        """Сканирует cookies с поочередным распределением payloads"""
        from queue import Queue
        from threading import Lock
        results = []

        for cookie_name, cookie_info in cookies_data.items():
            print(f"[*] Scanning cookie: {cookie_name}")

            payloads_queue = Queue()
            for payload in self.payloads:
                payloads_queue.put(payload)

            results_lock = Lock()

            def worker(cookie_name, cookie_template):
                while not payloads_queue.empty():
                    try:
                        payload = payloads_queue.get()
                        result = self._test_cookie_payload(cookie_name, cookie_template, payload)
                        if result:
                            with results_lock:
                                self.results['vulnerabilities'].append(result)
                                results.append(result)
                    except Exception as e:
                        print(f"[!] Error testing cookie payload {payload}: {e}")
                    finally:
                        payloads_queue.task_done()

            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                for _ in range(self.threads):
                    executor.submit(worker, cookie_name, cookie_info['template'])
                payloads_queue.join()

        return {
            'vector_type': 'cookies',
            'vulnerabilities_found': len(results),
            'scanned_cookies': list(cookies_data.keys())
        }

#endregion

#region Тестирование полезных нагрузок
    def _test_url_payload(self, base_url_parts, payload):
        #Тестирует payload в URL
        method = self.scan_settings.method.upper()
        test_url = base_url_parts[0] + payload + base_url_parts[1]

        print(f"[*] Testing {method} URL: {test_url}")
        response = self._send_request(url=test_url)
        is_vulnerable, details = self._detect_vulnerability(response, payload)

        if is_vulnerable:
            result = {
                'type': 'url_traversal',
                'url': test_url,
                'method': method,
                'payload': payload,
                'timestamp': datetime.now().isoformat(),
                'details': details
            }
            print(f"[+] Vulnerable URL found: {test_url}")
            return result
        return None

    def _test_request_body_payload(self, template, payload):
        #Тестирует payload в теле запроса (POST, PUT)
        method = self.scan_settings.method.upper()
        request_data = template.replace('*', payload)

        print(f"[*] Testing {method} payload: {payload}")
        response = self._send_request(data=request_data)
        is_vulnerable, details = self._detect_vulnerability(response, payload)

        if is_vulnerable:
            result = {
                'type': f'{method.lower()}_traversal',
                'url': self.scan_settings.url,
                'method': method,
                'payload': payload,
                'request_data': request_data,
                'timestamp': datetime.now().isoformat(),
                'details': details
            }
            print(f"[+] Vulnerable {method} request found with payload: {payload}")
            return result
        return None

    def _test_header_payload(self, header_name, template, payload):
        #Тестирует payload в заголовке
        method = self.scan_settings.method.upper()
        headers = self.scan_settings.headers.copy()
        headers[header_name] = template.replace('*', payload)

        print(f"[*] Testing {method} header {header_name}: {payload}")
        response = self._send_request(headers=headers)
        is_vulnerable, details = self._detect_vulnerability(response, payload)

        if is_vulnerable:
            result = {
                'type': 'header_traversal',
                'header': header_name,
                'url': self.scan_settings.url,
                'method': method,
                'payload': payload,
                'timestamp': datetime.now().isoformat(),
                'details': details
            }
            print(f"[+] Vulnerable header found: {header_name}")
            return result
        return None

    def _test_cookie_payload(self, cookie_name, template, payload):
      #Тестирует payload в cookie
        method = self.scan_settings.method.upper()
        cookies = self.scan_settings.cookies.copy()
        cookies[cookie_name] = template.replace('*', payload)

        print(f"[*] Testing {method} cookie {cookie_name}: {payload}")
        response = self._send_request(cookies=cookies)
        is_vulnerable, details = self._detect_vulnerability(response, payload)

        if is_vulnerable:
            result = {
                'type': 'cookie_traversal',
                'cookie': cookie_name,
                'url': self.scan_settings.url,
                'method': method,
                'payload': payload,
                'timestamp': datetime.now().isoformat(),
                'details': details
            }
            print(f"[+] Vulnerable cookie found: {cookie_name}")
            return result
        return None
#endregion

#region Сохранение результата

    def _save_results(self):
            print("Сохранение результатов")
            """Сохраняет результаты в JSON файл"""
            self.results['metadata']['end_time'] = datetime.now().isoformat()
            self.results['metadata']['elapsed_time'] = (
                    datetime.fromisoformat(self.results['metadata']['end_time']) -
                    datetime.fromisoformat(self.results['metadata']['start_time'])
            ).total_seconds()
            with open(self.results_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, ensure_ascii=False)
            if self.shell.lower() == 'yes':
                self._save_log_results()




    def _save_log_results(self):
            log_results = {
                'metadata': self.results['metadata'],
                'vulnerabilities': []
            }
            base_name, ext = os.path.splitext(self.results_file)
            log_file = f"{base_name}_shell{ext}"
            # Фильтруем уязвимости, содержащие "log" в payload
            TARGET_SUBSTRINGS = ["log", "expect", "php", "shell", "data", "=="]
            for vuln in self.results['vulnerabilities']:
                payload = vuln.get('payload', '').lower()
                if any(substring in payload for substring in TARGET_SUBSTRINGS):
                    log_results['vulnerabilities'].append(vuln)
            if log_results['vulnerabilities']:
                # Создаем имя файла для log-результатов
                with open(log_file, 'w', encoding='utf-8') as f:
                    json.dump(log_results, f, indent=2, ensure_ascii=False)
            print(f"Возможные файлы для проброса шелла записаны в {log_file}")


    def save_results(self):
       #Публичный метод для сохранения результатов
        self._save_results()

#endregion
