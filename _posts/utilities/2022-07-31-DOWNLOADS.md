---
title: Downloads
date: 2022-07-31 13:25:30 +/-TTTT
categories: [UTILITIES, Downloads]
tags: [downloads]     # TAG names should always be lowercase
---
Esta es una guia de cómo poder descargar archivos desde Windows a una máquina Linux



Para Descargar archivos desde Windows
```console
bitsadmin /transfer n http://10.10.10.100/prueba.txt C:\Users\arman\pruebaspenetracion\prueba.txt
```
{: .nolineno }

```console
certutil -urlcache -splt -f "http://10.10.10.100/prueba.txt"
```

```console
IWR -uri "http://10.10.10.10/prueba.txt" -Outfile prueba.txt
```
