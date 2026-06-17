# net

## Purpose
Networking and protocol implementation library for SageLang.

## Features
- **Protocols**: DNS, HTTP (Request/Server), WebSocket.
- **Core**: IP address handling, MIME types.

## Usage Example
```sage
import net.request
import net.url

let resp = net.request.get(url.parse("https://api.example.com"))
```
