# Fields that appear in Zeek logs, usually in files.log or related file-analysis logs. They describe what Zeek discovered about files transferred over the network.

tx_hosts  = who sent the file
rx_hosts  = who received the file
mime_type = what type of file
analyzers = what Zeek did to inspect it
extracted = where Zeek saved the file

tx_hosts: 5.39.93.210
rx_hosts: 192.168.1.10
mime_type: application/x-dosexec
analyzers: MD5,SHA1,EXTRACT
extracted: extract_files/HTTP-3f8a2.exe

1️⃣ 5.39.93.210 sent a file
2️⃣ 192.168.1.10 downloaded it
3️⃣ The file is a Windows executable
4️⃣ Zeek hashed it
5️⃣ Zeek extracted the file to disk

