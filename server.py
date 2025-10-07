# server.py
# A simple multi-threaded HTTP server implementing the required features.
# Handles GET for static files (HTML, binary), POST for JSON uploads.
# Includes thread pool, security, keep-alive, logging.
# Binary integrity: Files read in 'rb' mode, sent in 4KB chunks to preserve data without corruption.

import argparse
import socket
import threading
import queue
import logging
import os
import json
import random
import time
from datetime import datetime
import email.utils

# Set up logging with timestamps
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Global variables for thread pool management
conn_queue = queue.Queue()
thread_lock = threading.Lock()
busy_count = 0
max_threads = 10  # Default, set later
MAX_QUEUE_SIZE = 50  # For 503 when queue full

def parse_args():
    """Parse command-line arguments for host, port, and max threads."""
    parser = argparse.ArgumentParser(description='Multi-threaded HTTP Server')
    parser.add_argument('port', nargs='?', type=int, default=8080, help='Port number')
    parser.add_argument('host', nargs='?', default='127.0.0.1', help='Host address')
    parser.add_argument('max_threads', nargs='?', type=int, default=10, help='Maximum thread pool size')
    return parser.parse_args()

def parse_request(data):
    """Parse HTTP request into method, path, version, headers, and body."""
    if not data.strip():
        return None
    lines = data.splitlines()
    if len(lines) < 1:
        return None
    first_line = lines[0].strip().split()
    if len(first_line) < 3:
        return None
    method, path, version = first_line
    headers = {}
    i = 1
    while i < len(lines) and lines[i].strip():
        if ': ' in lines[i]:
            key, value = lines[i].split(': ', 1)
            headers[key.lower()] = value.strip()
        i += 1
    body = '\n'.join(lines[i:]) if i < len(lines) else ''
    return {'method': method, 'path': path, 'version': version, 'headers': headers, 'body': body}

def validate_host(req, host, port):
    """Validate Host header matches server address."""
    host_header = req['headers'].get('host', '').strip()
    if not host_header:
        return False, "missing"
    expected_hosts = [f"{host}:{port}", f"localhost:{port}"]
    if host == '127.0.0.1':
        expected_hosts.append(f"127.0.0.1:{port}")
    if host_header in expected_hosts:
        return True, ""
    return False, "mismatch"

def validate_path(path):
    """Check for path traversal attempts."""
    requested = path.lstrip('/')
    if '..' in requested or requested.startswith('..') or path.startswith('/') and len(path) > 1 and path[1] == '/':
        return False
    # Block ./ sequences that could be traversal
    if '/./' in path or path.startswith('./'):
        return False
    full_path = os.path.abspath(os.path.join('resources', requested))
    resources_base = os.path.abspath('resources')
    return full_path.startswith(resources_base + os.sep)

def send_error(client_sock, code, version='1.1'):
    """Send standard HTTP error response."""
    messages = {
        400: 'Bad Request', 403: 'Forbidden', 404: 'Not Found',
        405: 'Method Not Allowed', 415: 'Unsupported Media Type',
        500: 'Internal Server Error', 503: 'Service Unavailable'
    }
    msg = messages.get(code, 'Unknown Error')
    date_str = email.utils.formatdate()
    error_html = f"<html><body><h1>{code} {msg}</h1></body></html>"
    body_bytes = error_html.encode('utf-8')
    clen = len(body_bytes)
    headers = f"""HTTP/{version} {code} {msg}
Content-Type: text/html; charset=utf-8
Content-Length: {clen}
Date: {date_str}
Server: Multi-threaded HTTP Server
Connection: close
"""
    if code == 503:
        headers += "Retry-After: 5\r\n"
    response = (headers + "\r\n").encode('utf-8') + body_bytes
    client_sock.sendall(response)

def handle_get(client_sock, req, thread_name):
    """Handle GET request: serve HTML or binary files."""
    path = req['path']
    if path == '/':
        path = '/index.html'
    requested = path.lstrip('/')
    if not validate_path(path):
        send_error(client_sock, 403)
        logging.warning(f"[{thread_name}] Path traversal attempt: {path}")
        return
    full_path = os.path.join('resources', requested)
    if not os.path.exists(full_path):
        send_error(client_sock, 404)
        return
    ext = os.path.splitext(requested)[1].lower()
    try:
        if ext == '.html':
            with open(full_path, 'r', encoding='utf-8') as f:
                content = f.read()
            content_bytes = content.encode('utf-8')
            ctype = 'text/html; charset=utf-8'
            disposition = ''
        elif ext in ['.txt', '.png', '.jpg', '.jpeg']:
            with open(full_path, 'rb') as f:
                content_bytes = f.read()
            ctype = 'application/octet-stream'
            disposition = f'attachment; filename="{os.path.basename(full_path)}"'
        else:
            send_error(client_sock, 415)
            return
    except Exception:
        send_error(client_sock, 500)
        return
    date_str = email.utils.formatdate()
    clen = len(content_bytes)
    connection = 'keep-alive' if req['headers'].get('connection', '').lower() != 'close' and req['version'] != 'HTTP/1.0' else 'close'
    headers = f"""HTTP/1.1 200 OK
Content-Type: {ctype}
Content-Length: {clen}
Date: {date_str}
Server: Multi-threaded HTTP Server
Connection: {connection}
"""
    if connection == 'keep-alive':
        headers += "Keep-Alive: timeout=30, max=100\r\n"
    if disposition:
        headers += f"Content-Disposition: {disposition}\r\n"
    headers += "\r\n"
    client_sock.sendall(headers.encode('utf-8'))
    # Send content in 4KB chunks for efficient binary transfer
    chunk_size = 4096
    total_sent = 0
    for i in range(0, len(content_bytes), chunk_size):
        chunk = content_bytes[i:i + chunk_size]
        client_sock.sendall(chunk)
        total_sent += len(chunk)
    file_type = 'HTML' if ext == '.html' else 'binary'
    logging.info(f"[{thread_name}] Sending {file_type} file: {requested} ({total_sent} bytes)")
    logging.info(f"[{thread_name}] Response: 200 OK ({total_sent} bytes transferred)")

def handle_post(client_sock, req, thread_name):
    """Handle POST request: save JSON to uploads dir. Expects path /upload."""
    if req['path'] != '/upload':
        send_error(client_sock, 404)
        return
    ctype = req['headers'].get('content-type', '')
    if 'application/json' not in ctype.lower():
        send_error(client_sock, 415)
        return
    try:
        data = json.loads(req['body'])
    except json.JSONDecodeError:
        send_error(client_sock, 400)
        return
    uploads_dir = 'resources/uploads'
    os.makedirs(uploads_dir, exist_ok=True)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    rand_id = ''.join(random.choices('0123456789abcdef', k=4))
    filename = f"upload_{timestamp}_{rand_id}.json"
    filepath = os.path.join(uploads_dir, filename)
    try:
        with open(filepath, 'w') as f:
            json.dump(data, f)
        resp_data = {
            "status": "success",
            "message": "File created successfully",
            "filepath": f"/uploads/{filename}"
        }
        resp_body = json.dumps(resp_data).encode('utf-8')
        clen = len(resp_body)
        date_str = email.utils.formatdate()
        connection = 'keep-alive' if req['headers'].get('connection', '').lower() != 'close' and req['version'] != 'HTTP/1.0' else 'close'
        headers = f"""HTTP/1.1 201 Created
Content-Type: application/json
Content-Length: {clen}
Date: {date_str}
Server: Multi-threaded HTTP Server
Connection: {connection}
"""
        if connection == 'keep-alive':
            headers += "Keep-Alive: timeout=30, max=100\r\n"
        headers += "\r\n"
        client_sock.sendall(headers.encode('utf-8') + resp_body)
        logging.info(f"[{thread_name}] POST upload created: {filename}")
        logging.info(f"[{thread_name}] Response: 201 Created ({clen} bytes transferred)")
    except Exception:
        send_error(client_sock, 500)

def process_client(client_sock, addr, host, port, thread_name):
    """Process requests on a client socket with keep-alive support."""
    global busy_count
    with thread_lock:
        busy_count += 1
    client_sock.settimeout(30)
    req_count = 0
    while req_count < 100:
        try:
            data = client_sock.recv(8192).decode('utf-8', errors='ignore')
            if not data:
                break
            req = parse_request(data)
            if not req:
                send_error(client_sock, 400)
                break
            # Log request
            logging.info(f"[{thread_name}] Request: {req['method']} {req['path']} {req['version']}")
            # Host validation
            if 'host' not in req['headers']:
                send_error(client_sock, 400)
                logging.warning(f"[{thread_name}] Host validation failed: missing Host header")
                break
            valid, reason = validate_host(req, host, port)
            if not valid:
                send_error(client_sock, 403)
                logging.warning(f"[{thread_name}] Host validation failed: mismatched Host header")
                break
            logging.info(f"[{thread_name}] Host validation: {req['headers'].get('host', 'missing')} ✓")
            if req['method'] == 'GET':
                handle_get(client_sock, req, thread_name)
            elif req['method'] == 'POST':
                handle_post(client_sock, req, thread_name)
            else:
                send_error(client_sock, 405)
                logging.info(f"[{thread_name}] Response: 405 Method Not Allowed (0 bytes transferred)")
            req_count += 1
            # Check connection header
            conn_header = req['headers'].get('connection', '').lower()
            if conn_header == 'close' or req['version'] == 'HTTP/1.0':
                break
        except socket.timeout:
            logging.info(f"[{thread_name}] Connection timeout")
            break
        except Exception as e:
            logging.error(f"[{thread_name}] Error processing request: {e}")
            send_error(client_sock, 500)
            logging.info(f"[{thread_name}] Response: 500 Internal Server Error (0 bytes transferred)")
            break
    client_sock.close()
    log_msg = f"Connection closed after {req_count} requests" if req_count >= 100 else "Connection: keep-alive"
    logging.info(f"[{thread_name}] {log_msg}")
    with thread_lock:
        busy_count -= 1

def worker():
    """Worker thread: pulls connections from queue and processes them."""
    thread_name = threading.current_thread().name
    logging.info(f"[{thread_name}] Worker started")
    while True:
        client_sock, addr = conn_queue.get()
        logging.info(f"[{thread_name}] Connection from {addr[0]}:{addr[1]}")
        logging.info(f"[{thread_name}] Connection dequeued, assigned to {thread_name}")
        process_client(client_sock, addr, args.host, args.port, thread_name)
        conn_queue.task_done()

def log_pool_status():
    """Periodic logger for thread pool status."""
    while True:
        time.sleep(30)
        with thread_lock:
            current_busy = busy_count
        logging.info(f"Thread pool status: {current_busy}/{max_threads} active")

if __name__ == "__main__":
    args = parse_args()
    max_threads = args.max_threads  # Override default
    # Create resources/uploads if needed
    os.makedirs('resources/uploads', exist_ok=True)
    # Set up server socket
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((args.host, args.port))
    server_sock.listen(50)
    # Log startup
    logging.info(f"HTTP Server started on http://{args.host}:{args.port}")
    logging.info(f"Thread pool size: {args.max_threads}")
    logging.info("Serving files from 'resources' directory")
    logging.info("Press Ctrl+C to stop the server")
    # Start status logger
    status_thread = threading.Thread(target=log_pool_status, daemon=True)
    status_thread.start()
    # Start worker threads
    for i in range(args.max_threads):
        t = threading.Thread(target=worker, daemon=True)
        t.name = f"Thread-{i+1}"
        t.start()
    # Accept connections
    try:
        while True:
            client_sock, addr = server_sock.accept()
            with thread_lock:
                if busy_count >= max_threads and conn_queue.qsize() >= MAX_QUEUE_SIZE:
                    logging.warning("Thread pool saturated and queue full, sending 503")
                    send_error(client_sock, 503)
                    client_sock.close()
                    continue
                if busy_count >= max_threads:
                    logging.warning("Thread pool saturated, queuing connection")
            conn_queue.put((client_sock, addr))
    except KeyboardInterrupt:
        logging.info("Shutting down server...")
    finally:
        server_sock.close()