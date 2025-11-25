# Claude-Code-Inspector (CCI)

<p align="center">
  <strong>🔍 MITM Proxy for LLM API Traffic Analysis</strong>
</p>

<p align="center">
  A cross-platform command-line tool that intercepts, analyzes, and logs communications between AI coding assistants (Claude Code, Cursor, Codex, Gemini-CLI, etc.) and their backend LLM APIs.
</p>

---

## ✨ Features

- **Transparent Inspection** - See exactly what prompts are sent and what responses are received
- **Streaming Support** - Captures both streaming (SSE) and non-streaming API responses
- **Multi-Provider** - Works with Anthropic, OpenAI, Google, Groq, Together, Mistral, and more
- **Automatic Masking** - Protects API keys and sensitive data in logs
- **JSONL Output** - Structured data format for easy analysis and processing
- **Stream Merger** - Tool to consolidate streaming chunks into complete conversations
- **Cross-Platform** - Works on Windows, macOS, and Linux

## 📦 Installation

### Using pip

```bash
pip install claude-code-inspector
```

### Using uv (recommended)

```bash
uv add claude-code-inspector
```

### From source

```bash
git clone https://github.com/your-repo/claude-code-inspector.git
cd claude-code-inspector
uv sync
```

## 🚀 Quick Start

### 1. Start the Proxy

```bash
cci capture --port 8080 --output my_trace.jsonl
```

### 2. Configure Your Application

Set the proxy environment variables before running your AI tool:

```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
```

**Important for Node.js Applications (Claude Code, Cursor, etc.):**

Node.js applications require the `NODE_EXTRA_CA_CERTS` environment variable to trust the mitmproxy CA certificate:

```bash
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
```

### 3. Run Your AI Tool

```bash
# Example with Claude Code (full configuration)
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
claude -p "hello"

# Or Cursor, Codex, etc.
```

### 4. Stop Capture

Press `Ctrl+C` to stop the proxy.

### 5. (Optional) Merge Streaming Chunks

```bash
cci merge --input my_trace.jsonl --output merged.jsonl
```

## 📖 Certificate Installation

To intercept HTTPS traffic, you need to install the mitmproxy CA certificate.

### macOS

1. Run `cci capture` once to generate the certificate
2. Open the certificate:
   ```bash
   open ~/.mitmproxy/mitmproxy-ca-cert.pem
   ```
3. Double-click to add to Keychain
4. In Keychain Access, find "mitmproxy"
5. Double-click → Trust → "Always Trust"

### Linux (Ubuntu/Debian)

```bash
# Generate certificate first
cci capture &
sleep 2
kill %1

# Install certificate
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

### Linux (Fedora/RHEL)

```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /etc/pki/ca-trust/source/anchors/
sudo update-ca-trust
```

### Windows

1. Run `cci capture` once to generate the certificate
2. Navigate to `%USERPROFILE%\.mitmproxy\`
3. Double-click `mitmproxy-ca-cert.pem`
4. Click "Install Certificate"
5. Select "Local Machine" → Next
6. "Place all certificates in the following store"
7. Browse → "Trusted Root Certification Authorities"
8. Finish

### Certificate Help Command

```bash
cci config --cert-help
```


## 📋 CLI Reference

### `cci capture`

Start the proxy server and capture traffic.

```bash
cci capture [OPTIONS]

Options:
  -p, --port INTEGER     Proxy server port (default: 8080)
  -h, --host TEXT        Proxy server host (default: 127.0.0.1)
  -o, --output PATH      Output file path (default: cci_trace.jsonl)
  --debug                Enable debug mode with verbose logging
  -i, --include TEXT     Additional URL patterns to include (regex)
  -e, --exclude TEXT     URL patterns to exclude (regex)
```

**Examples:**

```bash
# Basic capture
cci capture

# Custom port and output
cci capture --port 9090 --output api_calls.jsonl

# Debug mode with custom filters
cci capture --debug --include ".*my-api\.com.*" --exclude ".*health.*"
```

### `cci merge`

Merge streaming response chunks into complete records.

```bash
cci merge --input <file> --output <file>

Options:
  -i, --input PATH   Input JSONL file with raw streaming chunks [required]
  -o, --output PATH  Output JSONL file for merged records [required]
```

**Example:**

```bash
cci merge --input raw_trace.jsonl --output conversations.jsonl
```

### `cci config`

Display configuration and setup help.

```bash
cci config [OPTIONS]

Options:
  --cert-help    Show certificate installation instructions
  --proxy-help   Show proxy configuration instructions
  --show         Show current configuration
```

### `cci stats`

Display statistics for a captured trace file.

```bash
cci stats <file>
```

**Example:**

```bash
cci stats my_trace.jsonl
```

## 📄 Output Format

CCI produces JSONL (JSON Lines) files with the following record types:

### Request Record

```json
{
  "type": "request",
  "id": "uuid-req-001",
  "timestamp": "2024-11-25T10:00:00Z",
  "method": "POST",
  "url": "https://api.anthropic.com/v1/messages",
  "headers": {"content-type": "application/json"},
  "body": {"model": "claude-3-sonnet", "messages": [...]}
}
```

### Response Chunk (Streaming)

```json
{
  "type": "response_chunk",
  "request_id": "uuid-req-001",
  "timestamp": "2024-11-25T10:00:01Z",
  "status_code": 200,
  "chunk_index": 0,
  "content": {"type": "content_block_delta", "delta": {"text": "Hello"}}
}
```

### Response Meta

```json
{
  "type": "response_meta",
  "request_id": "uuid-req-001",
  "total_latency_ms": 1500,
  "status_code": 200,
  "total_chunks": 42
}
```

### Non-Streaming Response

```json
{
  "type": "response",
  "request_id": "uuid-req-001",
  "timestamp": "2024-11-25T10:00:01Z",
  "status_code": 200,
  "headers": {...},
  "body": {...},
  "latency_ms": 1500
}
```

### Merged Record (after `cci merge`)

```json
{
  "request_id": "uuid-req-001",
  "timestamp": "2024-11-25T10:00:00Z",
  "method": "POST",
  "url": "https://api.anthropic.com/v1/messages",
  "request_body": {...},
  "response_status": 200,
  "response_text": "Hello! How can I help you today?",
  "total_latency_ms": 1500,
  "chunk_count": 42
}
```

## ⚙️ Configuration

CCI can be configured via TOML/YAML files or environment variables.

### Configuration File

Create `cci.toml` in your current directory or `~/.config/cci/config.toml`:

```toml
[proxy]
host = "127.0.0.1"
port = 8080
ssl_insecure = false

[filter]
include_patterns = [
    ".*api\\.anthropic\\.com.*",
    ".*api\\.openai\\.com.*",
    ".*generativelanguage\\.googleapis\\.com.*",
]
exclude_patterns = []

[masking]
mask_auth_headers = true
sensitive_headers = ["authorization", "x-api-key", "api-key"]
sensitive_body_fields = []
mask_pattern = "***MASKED***"

[storage]
output_file = "cci_trace.jsonl"
pretty_json = false
max_file_size_mb = 0  # 0 = no rotation

[logging]
level = "INFO"
log_file = ""  # optional file path
```

### Environment Variables

```bash
CCI_PROXY_HOST=127.0.0.1
CCI_PROXY_PORT=8080
CCI_OUTPUT_FILE=my_trace.jsonl
CCI_LOG_LEVEL=DEBUG
CCI_INCLUDE_PATTERNS=.*my-api\.com.*,.*other-api\.com.*
```

## 🔧 Supported LLM Providers

CCI is pre-configured to capture traffic from:

| Provider | API Domain |
|----------|------------|
| Anthropic | `api.anthropic.com` |
| OpenAI | `api.openai.com` |
| Google | `generativelanguage.googleapis.com` |
| Together | `api.together.xyz` |
| Groq | `api.groq.com` |
| Mistral | `api.mistral.ai` |
| Cohere | `api.cohere.ai` |
| DeepSeek | `api.deepseek.com` |

Add custom providers with `--include` or in the config file.

## 🐛 Troubleshooting

### SSL Handshake Error

**Problem:** `SSL: CERTIFICATE_VERIFY_FAILED`

**Solution:**
1. Ensure the mitmproxy CA certificate is installed
2. Run `cci config --cert-help` for instructions
3. For testing, some tools support `--insecure` or `verify=False`

### Node.js Apps Not Working (Claude Code, Cursor, etc.)

**Problem:** Requests hang or timeout when using Claude Code or other Node.js-based tools

**Solution:**
Node.js requires the `NODE_EXTRA_CA_CERTS` environment variable to trust custom CA certificates:

```bash
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
```

Make sure all three variables are set:
```bash
export HTTP_PROXY=http://127.0.0.1:8080
export HTTPS_PROXY=http://127.0.0.1:8080
export NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
```

### Proxy Connection Refused

**Problem:** `Connection refused` when connecting through proxy

**Solution:**
1. Ensure CCI is running: `cci capture`
2. Check the port is correct: `--port 8080`
3. Check firewall settings

### No Traffic Captured

**Problem:** CCI is running but no requests are logged

**Solution:**
1. Verify proxy environment variables are set:
   ```bash
   echo $HTTP_PROXY $HTTPS_PROXY
   ```
2. Check URL filter patterns match your API:
   ```bash
   cci config --show
   ```
3. Add custom include pattern:
   ```bash
   cci capture --include ".*your-api\.com.*"
   ```

### High Memory Usage with Long Sessions

**Problem:** Memory grows during long capture sessions

**Solution:**
Configure log rotation in `cci.toml`:
```toml
[storage]
max_file_size_mb = 100
```

## 📜 License

MIT License

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📞 Support

- GitHub Issues: [Report a bug](https://github.com/chouzz/claude-code-inspector/issues)
- Documentation: [Read the docs](https://github.com/chouzz/claude-code-inspector#readme)

