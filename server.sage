# TCP and HTTP server framework
# Builds on native tcp module for high-level server patterns

import tcp

# HTTP status line builder
proc status_line(code, text):
    return "HTTP/1.1 " + str(code) + " " + text + chr(13) + chr(10)

# Build a complete HTTP response string
proc http_response(code, status_text, content_type, body):
    let resp = status_line(code, status_text)
    resp = resp + "Content-Type: " + content_type + chr(13) + chr(10)
    resp = resp + "Content-Length: " + str(len(body)) + chr(13) + chr(10)
    resp = resp + "Connection: close" + chr(13) + chr(10)
    resp = resp + chr(13) + chr(10)
    resp = resp + body
    return resp

# Build common responses
proc response_ok(body, content_type):
    return http_response(200, "OK", content_type, body)

proc response_json(body):
    return http_response(200, "OK", "application/json", body)

proc response_html(body):
    return http_response(200, "OK", "text/html", body)

proc response_text(body):
    return http_response(200, "OK", "text/plain", body)

proc response_not_found(body):
    return http_response(404, "Not Found", "text/plain", body)

proc response_redirect(url):
    let resp = status_line(302, "Found")
    resp = resp + "Location: " + url + chr(13) + chr(10)
    resp = resp + "Content-Length: 0" + chr(13) + chr(10)
    resp = resp + chr(13) + chr(10)
    return resp

proc response_error(code, message):
    return http_response(code, message, "text/plain", message)

# Parse an incoming HTTP request from raw data
proc parse_request(raw):
    let req = {}
    req["method"] = ""
    req["path"] = "/"
    req["version"] = ""
    req["headers"] = {}
    req["body"] = ""
    req["query"] = ""
    req["raw"] = raw

    # Find end of request line
    let line_end = 0
    let line_found = false
    for i in range(len(raw)):
        if not line_found and raw[i] == chr(10):
            line_end = i
            line_found = true

    # Parse request line: "GET /path HTTP/1.1"
    let request_line = ""
    for i in range(line_end):
        let c = raw[i]
        if c != chr(13):
            request_line = request_line + c

    # Split by spaces
    let parts = []
    let current = ""
    for i in range(len(request_line)):
        if request_line[i] == " ":
            if len(current) > 0:
                push(parts, current)
            current = ""
        else:
            current = current + request_line[i]
    if len(current) > 0:
        push(parts, current)

    if len(parts) >= 1:
        req["method"] = parts[0]
    if len(parts) >= 2:
        let full_path = parts[1]
        # Split path and query
        let q_pos = -1
        for i in range(len(full_path)):
            if q_pos < 0 and full_path[i] == "?":
                q_pos = i
        if q_pos >= 0:
            let p = ""
            for i in range(q_pos):
                p = p + full_path[i]
            req["path"] = p
            let q = ""
            for i in range(len(full_path) - q_pos - 1):
                q = q + full_path[q_pos + 1 + i]
            req["query"] = q
        else:
            req["path"] = full_path
    if len(parts) >= 3:
        req["version"] = parts[2]

    # Parse headers
    let pos = line_end + 1
    while pos < len(raw):
        let h_end = pos
        while h_end < len(raw) and raw[h_end] != chr(10):
            h_end = h_end + 1
        let header_line = ""
        for i in range(h_end - pos):
            let c = raw[pos + i]
            if c != chr(13):
                header_line = header_line + c
        pos = h_end + 1
        if len(header_line) == 0:
            break
        # Parse "Key: Value"
        let colon = -1
        for i in range(len(header_line)):
            if colon < 0 and header_line[i] == ":":
                colon = i
        if colon > 0:
            let key_parts = []
            for i in range(colon):
                let c = header_line[i]
                let code = ord(c)
                if code >= 65 and code <= 90:
                    push(key_parts, chr(code + 32))
                else:
                    push(key_parts, c)
            let key = join(key_parts, "")
            let val_parts = []
            let start = colon + 1
            while start < len(header_line) and header_line[start] == " ":
                start = start + 1
            for i in range(len(header_line) - start):
                push(val_parts, header_line[start + i])
            let val = join(val_parts, "")
            req["headers"][key] = val

    # Read body (chunked or raw)
    if req["headers"]["transfer-encoding"] == "chunked":
        let body_parts = []
        while pos < len(raw):
            let size_end = pos
            while size_end < len(raw) and raw[size_end] != chr(10):
                size_end = size_end + 1
            let size_line_parts = []
            for i in range(size_end - pos):
                let c = raw[pos + i]
                if c != chr(13):
                    push(size_line_parts, c)
            let size_line = join(size_line_parts, "")
            pos = size_end + 1
            if len(size_line) == 0:
                req["body"] = join(body_parts, "")
                return req
            let chunk_size = 0
            for i in range(len(size_line)):
                let c = ord(size_line[i])
                let val = -1
                if c >= 48 and c <= 57:
                    val = c - 48
                elif c >= 65 and c <= 70:
                    val = c - 55
                elif c >= 97 and c <= 102:
                    val = c - 87
                if val >= 0:
                    chunk_size = chunk_size * 16 + val
            if chunk_size == 0:
                req["body"] = join(body_parts, "")
                return req
            if pos + chunk_size <= len(raw):
                for i in range(chunk_size):
                    push(body_parts, raw[pos + i])
                pos = pos + chunk_size
                if pos < len(raw) and raw[pos] == chr(13):
                    pos = pos + 1
                if pos < len(raw) and raw[pos] == chr(10):
                    pos = pos + 1
            else:
                req["body"] = join(body_parts, "")
                return req
        req["body"] = join(body_parts, "")
        return req

    # Non-chunked body (remaining raw data)
    let body_parts = []
    while pos < len(raw):
        push(body_parts, raw[pos])
        pos = pos + 1
    req["body"] = join(body_parts, "")
    return req

# Route table: maps method+path to handler functions
proc create_router():
    let router = {}
    router["routes"] = []
    router["not_found_handler"] = nil
    return router

# Add a route to the router
proc route(router, method, path, handler):
    let r = {}
    r["method"] = method
    r["path"] = path
    r["handler"] = handler
    push(router["routes"], r)

# Add GET route
proc get_route(router, path, handler):
    route(router, "GET", path, handler)

# Add POST route
proc post_route(router, path, handler):
    route(router, "POST", path, handler)

# Set 404 handler
proc set_not_found(router, handler):
    router["not_found_handler"] = handler

# Match a request against routes
proc dispatch(router, req):
    let routes = router["routes"]
    for i in range(len(routes)):
        let r = routes[i]
        if r["method"] == req["method"] and r["path"] == req["path"]:
            return r["handler"](req)
    if router["not_found_handler"] != nil:
        return router["not_found_handler"](req)
    return response_not_found("404 Not Found: " + req["path"])

# Create a server configuration
proc create_server(host, port):
    let srv = {}
    srv["host"] = host
    srv["port"] = port
    srv["router"] = create_router()
    srv["running"] = false
    srv["max_request_size"] = 65536
    return srv

# Serve one request on an accepted client connection
proc handle_client(srv, client):
    let raw = tcp.recvall(client, srv["max_request_size"])
    if raw != nil and len(raw) > 0:
        let req = parse_request(raw)
        let resp = dispatch(srv["router"], req)
        tcp.sendall(client, resp)
    tcp.close(client)

# Start the server (blocking - serves one request at a time)
proc listen_and_serve(srv):
    let listener = tcp.listen(srv["host"], srv["port"])
    if listener == nil:
        return false
    srv["running"] = true
    while srv["running"]:
        let client = tcp.accept(listener)
        if client != nil:
            handle_client(srv, client)
    tcp.close(listener)
    return true

# Stop the server
proc shutdown(srv):
    srv["running"] = false
