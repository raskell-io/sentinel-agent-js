# sentinel-agent-js

JavaScript scripting agent for [Sentinel](https://github.com/raskell-io/sentinel) reverse proxy. Write custom request/response processing logic in JavaScript.

## Features

- Execute JavaScript scripts on request/response lifecycle events
- Fast, lightweight QuickJS engine (via rquickjs)
- Console API for logging (console.log, console.warn, console.error)
- Return-based decision model (allow, block, redirect)
- Header manipulation (add/remove request and response headers)
- Fail-open mode for graceful error handling

## Installation

### From crates.io

```bash
cargo install sentinel-agent-js
```

### From source

```bash
git clone https://github.com/raskell-io/sentinel-agent-js
cd sentinel-agent-js
cargo build --release
```

## Usage

```bash
sentinel-js-agent --socket /var/run/sentinel/js.sock \
  --script /etc/sentinel/scripts/handler.js
```

### Command Line Options

| Option | Environment Variable | Description | Default |
|--------|---------------------|-------------|---------|
| `--socket` | `AGENT_SOCKET` | Unix socket path | `/tmp/sentinel-js.sock` |
| `--script` | `JS_SCRIPT` | JavaScript script file | (required) |
| `--verbose` | `JS_VERBOSE` | Enable debug logging | `false` |
| `--fail-open` | `FAIL_OPEN` | Allow requests on script errors | `false` |

## Writing Scripts

### Basic Example

```javascript
function on_request_headers(request) {
    // Block admin access
    if (request.uri.includes("/admin")) {
        return { decision: "block", status: 403, body: "Forbidden" };
    }

    // Allow all other requests
    return { decision: "allow" };
}
```

### Available Hooks

| Hook | Description |
|------|-------------|
| `on_request_headers(request)` | Called when request headers are received |
| `on_response_headers(response)` | Called when response headers are received |

### Request Object

```javascript
{
    method: "GET",           // HTTP method
    uri: "/api/users",       // Request URI with query string
    client_ip: "192.168.1.1", // Client IP address
    correlation_id: "abc123", // Request correlation ID
    headers: {               // Request headers (name -> value)
        "Content-Type": "application/json",
        "User-Agent": "Mozilla/5.0..."
    }
}
```

### Response Object

```javascript
{
    status: 200,             // HTTP status code
    correlation_id: "abc123", // Request correlation ID
    headers: {               // Response headers (name -> value)
        "Content-Type": "application/json",
        "X-Custom": "value"
    }
}
```

### Return Values

Scripts should return a decision object:

```javascript
// Allow the request
return { decision: "allow" };

// Block with custom status and body
return { decision: "block", status: 403, body: "Access Denied" };

// Redirect to another URL
return { decision: "redirect", status: 302, body: "https://example.com/login" };
```

### Header Manipulation

```javascript
function on_request_headers(request) {
    return {
        decision: "allow",
        add_request_headers: {
            "X-Processed-By": "js-agent",
            "X-Client-IP": request.client_ip
        },
        remove_request_headers: ["X-Debug"],
        add_response_headers: {
            "X-Frame-Options": "DENY"
        }
    };
}
```

### Audit Tags

Add tags for logging and analytics:

```javascript
function on_request_headers(request) {
    if (request.headers["User-Agent"]?.includes("bot")) {
        return {
            decision: "allow",
            tags: ["bot-detected", "monitoring"]
        };
    }
    return { decision: "allow" };
}
```

### Console Logging

```javascript
function on_request_headers(request) {
    console.log("Processing request:", request.uri);
    console.warn("Warning message");
    console.error("Error message");
    return { decision: "allow" };
}
```

## Examples

### Block Bad User-Agents

```javascript
function on_request_headers(request) {
    const ua = request.headers["User-Agent"] || "";
    const badBots = ["sqlmap", "nikto", "nessus", "masscan"];

    for (const bot of badBots) {
        if (ua.toLowerCase().includes(bot)) {
            return {
                decision: "block",
                status: 403,
                tags: ["bot-blocked", bot]
            };
        }
    }
    return { decision: "allow" };
}
```

### Rate Limit by Path

```javascript
function on_request_headers(request) {
    // Add rate limit tier based on path
    let tier = "standard";
    if (request.uri.startsWith("/api/v1/")) {
        tier = "api";
    } else if (request.uri.startsWith("/admin/")) {
        tier = "admin";
    }

    return {
        decision: "allow",
        add_request_headers: {
            "X-Rate-Limit-Tier": tier
        }
    };
}
```

### Require Authentication

```javascript
function on_request_headers(request) {
    // Skip for public paths
    if (request.uri.startsWith("/public/") || request.uri === "/health") {
        return { decision: "allow" };
    }

    // Check for auth header
    if (!request.headers["Authorization"]) {
        return {
            decision: "block",
            status: 401,
            body: "Authentication required"
        };
    }

    return { decision: "allow" };
}
```

### Add Security Headers

```javascript
function on_response_headers(response) {
    return {
        decision: "allow",
        add_response_headers: {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000"
        }
    };
}
```

## Sentinel Proxy Configuration

```kdl
agents {
    agent "js" {
        type "custom"
        transport "unix_socket" {
            path "/var/run/sentinel/js.sock"
        }
        events ["request_headers", "response_headers"]
        timeout-ms 100
        failure-mode "open"
    }
}
```

## Error Handling

When `--fail-open` is enabled, script errors will:
- Log the error
- Allow the request to proceed
- Add `js-error` and `fail-open` tags to audit metadata

When `--fail-open` is disabled (default), script errors will:
- Log the error
- Block the request with 500 status
- Add `js-error` tag to audit metadata

## Comparison with sentinel-agent-lua

| Feature | sentinel-agent-js | sentinel-agent-lua |
|---------|------------------|-------------------|
| Engine | QuickJS | mlua (Lua 5.4) |
| Scripting | Single script file | Multiple scripts with metadata |
| Hot Reload | No | Yes |
| VM Pooling | No | Yes |
| Resource Limits | Minimal | Comprehensive (memory, CPU, time) |
| Standard Library | Basic (console) | Rich (JSON, crypto, regex, etc.) |
| Use Case | Simple scripts | Production workloads |

Use `sentinel-agent-js` for:
- Simple request filtering logic
- Quick prototyping
- Lightweight deployments

Use `sentinel-agent-lua` for:
- Complex processing logic
- Production environments with strict resource limits
- Multiple scripts with hot reload

## Development

```bash
# Run with debug logging
RUST_LOG=debug cargo run -- --socket /tmp/test.sock --script ./test.js --verbose

# Run tests
cargo test
```

## License

MIT OR Apache-2.0
