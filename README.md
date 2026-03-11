# Cyber Defense Command Reference

A searchable command reference for cybersecurity operations, threat hunting, incident response, and detection engineering.

---

# Command Index

## Encoding / Decoding

base64 decode | echo <base64> | base64 -d  
base64 decode + detect file type | echo <base64> | base64 -d | file -  
base64 encode | echo "text" | base64  

---

## PCAP Analysis

extract readable strings from pcap | strings -n 10 capture.pcap  
save extracted strings | strings -n 10 capture.pcap > capture-strings.txt  
analyze pcap with zeek | zeek -r capture.pcap  
read packets in pcap | tcpdump -r capture.pcap  

---

## Zeek / JSON Logs

pretty print json | jq .  
extract json field | jq '.field'  
filter json value | jq 'select(.field=="value")'  

---

## Log Searching

search keyword | grep "text" file  
recursive search | grep -r "text" .  
case insensitive search | grep -i "text" file  
count matches | grep -c "text" file  

---

## File Analysis

detect file type | file filename  
detect file type from pipe | file -  
view printable strings | strings file  
extract long strings | strings -n 10 file  
hex view file | xxd file  

---

## Lab Utilities

record terminal session | script lab_record.txt  
show command history | history  
save command history | history > commands.txt  
