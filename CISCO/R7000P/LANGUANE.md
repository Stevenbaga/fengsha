# Netgear R7000P V1.3.0.8

### version

```
V1.3.0.8
```

### Firmware

```
(http://support.netgear.cn/doucument/More.asp?id=2350)
```



## sub_D199C

### detail

In function sub_D199C,the content obtained by the program from the parameter "country" and "purchase_date" are passed to v8 and v7 values.Then the v8 and v7 are directly copied into the v12 and v11 stack through the strcpy function.There is no size check, so there is a stack overflow vulnerability.The attacker can easily perform a Deny of Service Attack or Remote Code Execution with carefully crafted overflow data.

```c
int __fastcall sub_D199C(int a1, int a2)
{
  size_t v4; // r0
  size_t v5; // r0
  char v7[2040]; // [sp+8h] [bp-17B8h] BYREF
  char v8[2040]; // [sp+808h] [bp-FB8h] BYREF
  char v9[1016]; // [sp+1008h] [bp-7B8h] BYREF
  _BYTE v10[248]; // [sp+1408h] [bp-3B8h] BYREF
  char v11[248]; // [sp+1508h] [bp-2B8h] BYREF
  char v12[248]; // [sp+1608h] [bp-1B8h] BYREF
  char v13[184]; // [sp+1708h] [bp-B8h] BYREF

  puts("Product Register...");
  websgetvar(a1, "country", v8, 2048);
  strcpy(v12, v8);
  bd_read_sn(v10, 255);
  websgetvar(a1, "purchase_date", v7, 2048);
  strcpy(v11, v7);
  if ( sso_product_register(v10, v13) )
  {
    strcpy(v9, "[BitDefender] SSO_API_PRODUCT_REGISTER fail");
    v4 = strlen(v9);
    ambitWriteLog(v9, v4, 67108903);
    printf("Login fail status=%s, message=%s, code=%s, error_code=%s\n", v13, &v13[24], &v13[8], &v13[16]);
    acosNvramConfig_set("sso_error_message", &v13[24]);
    sprintf(v9, "Registration fail status=%s, message=%s, code=%s, error_code=%s\n", v13, &v13[24], &v13[8], &v13[16]);
    v5 = strlen(v9);
    ambitWriteLog(v9, v5, 67108903);
  }
  else
  {
    bd_read_sn(v10, 255);
    strcpy(v11, "2018-09-14T14:24:10.487");
    sso_search_by_serial(v13);
    memset(v13, 0, 0x98u);
    sso_getuserprofile(v13);
  }
  sub_1B9E8("genie_armor_activating.htm", a2);
  return 0;
}
```



### poc

```python
To reproduce the vulnerability, the following steps can be followed:

Start frimware through QEMU system or other methods (real device)
Use the default username and password to login web.
Execute the poc script POC_for_formSystemCheck.py as follows:
```
python3 POC_for_formSystemCheck.py 192.168.1.1
