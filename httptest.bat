@echo off

TLSClient.exe howsmyssl.com 443 002f 0 "GET / HTTP/1.1" 
TLSClient.exe howsmyssl.com 443 0035 0 "GET / HTTP/1.1" 
TLSClient.exe intel.com 443 003c 0 "GET / HTTP/1.1" 
TLSClient.exe intel.com 443 003d 0 "GET / HTTP/1.1" 
TLSClient.exe yahoo.com 443 009c 0 "GET / HTTP/1.1" 
TLSClient.exe yahoo.com 443 009d 0 "GET / HTTP/1.1" 
TLSClient.exe pulsesecure.net 443 c02f 0 "GET / HTTP/1.1" 
