# TLS 1.2 Client written in .NET

## Summary:

This is a TLS 1.2 Client written entirely in .NET. It currently supports 
the following ciphers:

* 0x2f - TLS_RSA_WITH_AES_128_CBC_SHA
* 0x35 - TLS_RSA_WITH_AES_256_CBC_SHA
* 0x3c - TLS_RSA_WITH_AES_128_CBC_SHA256
* 0x3d - TLS_RSA_WITH_AES_256_CBC_SHA256
* 0x9c - TLS_RSA_WITH_AES_128_GCM_SHA256
* 0x9d - TLS_RSA_WITH_AES_256_GCM_SHA384

Work is being done to support TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
 and TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA.

_NOTE: This is just done for learning. Hope it helps someone who wants to learn
TLS. If someone can contribute to adding the above ciphers, it would be great!_

## Compilation:

Please execute the following commands:

```
C:\TLS_1.2_Client> compileDLL.bat


C:\TLS_1.2_Client> compile.bat
```  

## Execution:

The executable named TLSClient.exe will be generated in the same folder. 
 Please execute it as follows:

```
C:\TLS_1.2_Client>TLSClient.exe
     
Example: TLSClient.exe 10.209.113.104 443 002f 1 "GET / HTTP/1.1"

C:\TLS_1.2_Client>
C:\TLS_1.2_Client>TLSClient.exe intel.com 443 003d 2 "GET / HTTP/1.1"
HTTP/1.1 301 Moved Permanently
Content-length: 0
Location: https://www./
Connection: close

C:\TLS_1.2_Client>
```
  
