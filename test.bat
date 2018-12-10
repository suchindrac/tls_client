@echo off

echo Testing TLS_RSA_WITH_AES_128_CBC_SHA (0x2f)
echo ---- TLS_RSA_WITH_AES_128_CBC_SHA (0x2f) ---- > output.txt
TLSClient.exe howsmyssl.com 443 002f 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_RSA_WITH_AES_256_CBC_SHA (0x35)
echo ---- TLS_RSA_WITH_AES_256_CBC_SHA (0x35) ---- >> output.txt
TLSClient.exe howsmyssl.com 443 0035 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_RSA_WITH_AES_128_CBC_SHA256 (0x3c)
echo ---- TLS_RSA_WITH_AES_128_CBC_SHA256 (0x3c) ---- >> output.txt
TLSClient.exe intel.com 443 003c 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_RSA_WITH_AES_256_CBC_SHA256 (0x3d)
echo ---- TLS_RSA_WITH_AES_256_CBC_SHA256 (0x3d) ---- >> output.txt
TLSClient.exe intel.com 443 003d 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9c)
echo ---- TLS_RSA_WITH_AES_128_GCM_SHA256 (0x9c) ---- >> output.txt
TLSClient.exe yahoo.com 443 009c 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9d)
echo ---- TLS_RSA_WITH_AES_256_GCM_SHA384 (0x9d) ---- >> output.txt
TLSClient.exe yahoo.com 443 009d 1 "GET / HTTP/1.1" >> output.txt
echo Testing TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f)
echo ---- TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) ---- >> output.txt
TLSClient.exe pulsesecure.net 443 c02f 1 "GET / HTTP/1.1" >> output.txt
echo ------------------------------------------------------------- >> output.txt
