# Multi-threaded HTTP Server

A from-scratch implementation of a multi-threaded HTTP server using Python sockets. Supports GET for static HTML/binary files (with aesthetic CSS styling) and POST for JSON uploads, with full security, keep-alive, and detailed logging as per requirements.

## Build and Run Instructions

No compilation needed – pure Python 3.6+.

1. Ensure Python 3 is installed.
2. Create the project structure with all files (server.py, resources/ including HTML with CSS, TXT, PNG/JPG images, uploads/ dir).
3. Run: `python server.py [port] [host] [max_threads]`
   - Defaults: port=8080, host=127.0.0.1, max_threads=10
   - Example: `python server.py 8000 0.0.0.0 20`

Server binds to specified host/port, listens with queue=50. Test with browser/curl. Ctrl+C to stop. Handles persistent/non-persistent sockets properly.

## Binary Transfer Implementation

- HTML: Served as text with `text/html; charset=utf-8` for inline rendering (includes modern CSS: gradients, flexbox, responsive design).
- Binary (TXT/PNG/JPG): Read in `'rb'` mode, transferred as `application/octet-stream` with `Content-Disposition: attachment; filename=...` for downloads.
- Efficiency: 4KB chunks for large files (>1MB) to prevent memory overload; integrity preserved (verify with `md5sum original.jpg downloaded.jpg` – matches exactly).
- Unsupported types: 415 error.

## Thread Pool Architecture

- Fixed worker pool (configurable, default 10) using `threading.Thread` daemons.
- Connections queued in `queue.Queue()` if saturated; workers pull via `get()`/`task_done()`.
- Sync: `threading.Lock()` for busy_count to avoid races/deadlocks.
- Logging: Saturation warnings, dequeue assignments, status every 30s (e.g., "8/10 active").
- Concurrency: Handles 5+ simultaneous large file downloads; queues excess.

## Security Measures Implemented

- **Path Traversal**: `os.path.normpath()` canonicalizes; rejects `..`/`/` escapes outside `resources/` (403 Forbidden). Blocks e.g., `/../etc/passwd`, `//config`.
- **Host Validation**: Matches `Host` header to server (e.g., `localhost:8080`); missing=400, mismatch=403. Logs violations.
- All requests validated; no absolute paths allowed.

## Known Limitations

- HTTP/1.1 only (no HTTP/2); no HTTPS.
- Queue unlimited (logs saturation but no hard 503 on queue full).
- No auth/caching/gzip; educational focus.
- Images: Ensure 2+ PNG (1>1MB), 2+ JPG (1>1MB) in resources/.

## Testing

### Basic
- `curl http://localhost:8080/` → index.html (aesthetic page).
- `curl http://localhost:8080/about.html` → Styled about page.
- `curl -O http://localhost:8080/img1.png` → Downloads PNG (checksum match).
- `curl -O http://localhost:8080/big_photo.jpg` → Large JPG download.
- `curl -O http://localhost:8080/sample.txt` → TXT as binary.
- `curl -X POST -H "Content-Type: application/json" -d '{"key":"value"}' http://localhost:8080/` → 201 with /uploads/upload_... .json.
- `curl http://localhost:8080/nonexistent.png` → 404.
- `curl -X PUT http://localhost:8080/` → 405.

### Binary Integrity
- Download large files; `md5sum` originals vs. downloads (100% match, no corruption).

### Security
- `curl http://localhost:8080/../etc/passwd` → 403.
- `curl -H "Host: evil.com" http://localhost:8080/` → 403.
- `curl -X POST -H "Content-Type: text/plain" -d "not json" http://localhost:8080/` → 415.

### Concurrency
- `ab -n 50 -c 5 http://localhost:8080/big_photo.jpg` → Handles queuing/multiple clients.

### Sample JSON for POST
Create `test.json`: `{"name": "Test User", "message": "Sample upload data"}`  
Test: `curl -X POST -H "Content-Type: application/json" -d @test.json http://localhost:8080/`