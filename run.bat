@echo off

if [%1] EQU [] (
GOTO INVALID
)
TLSClient.exe pulsesecure.net 443 c02f %1 "GET / HTTP/1.1"

GOTO DONE

:INVALID

echo Invalid Argument

:DONE

echo DONE