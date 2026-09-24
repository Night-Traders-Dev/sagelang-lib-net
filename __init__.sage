import net.ip
import net.url
import net.request
import net.server
import net.dns
import net.headers
import net.mime
import net.websocket
import socket
import tcp
import http

let resolve = socket.resolve
let strerror = socket.strerror
let connect = tcp.connect
let listen = tcp.listen
let accept = tcp.accept
let send = tcp.send
let recv = tcp.recv
let sendall = tcp.sendall
let recvall = tcp.recvall
let recvline = tcp.recvline
let close = tcp.close
let http_get = http.get
let http_post = http.post
let http_put = http.put
let http_delete = http.delete
let http_patch = http.patch
let http_head = http.head
let http_download = http.download
let http_escape = http.escape
let http_unescape = http.unescape
