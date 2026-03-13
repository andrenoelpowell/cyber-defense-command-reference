## Zeek File Analysis Fields

These fields appear in **Zeek logs**, usually in `files.log` or related file-analysis logs.  
They describe what Zeek discovered about **files transferred over the network**.

### Field Meanings

| Field | Description |
|------|-------------|
| `tx_hosts` | Host(s) that **sent** the file |
| `rx_hosts` | Host(s) that **received** the file |
| `mime_type` | The **file type** Zeek identified |
| `analyzers` | The **analysis modules** Zeek used on the file |
| `extracted` | The **location where Zeek saved the extracted file** |

---


---

### Interpretation

1. **5.39.93.210** sent a file  
2. **192.168.1.10** downloaded the file  
3. The file is a **Windows executable (`.exe`)**  
4. Zeek generated **MD5 and SHA1 hashes**  
5. Zeek **extracted the file to disk** for further analysis

---

### Why This Matters

These fields help analysts detect:

- Malware downloads
- Suspicious file transfers
- Payload delivery during an intrusion
- Files that should be investigated or hashed for threat intel
