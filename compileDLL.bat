del *.dll
csc /target:library /out:common.dll common.cs
csc /target:library /reference:common.dll /reference:System.Numerics.dll /out:crypto.dll crypto.cs
csc /target:library /reference:common.dll /out:handshake.dll /reference:System.Numerics.dll handshake.cs
csc /target:library /reference:common.dll /out:LibTLSClient.dll /reference:handshake.dll /reference:crypto.dll LibTLSClient.cs

