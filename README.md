# End-to-End Threat Hunting with a Manually Deployed Elastic Stack

## 1. Project Objective

This project simulates a real-world Security Operations Center (SOC) task: manually building a Security Information and Event Management (SIEM) pipeline from scratch to detect a common, obfuscated attack.

The goal was to deploy the core components of the Elastic Stack (Elasticsearch and Kibana) on a Linux server, configure a Windows endpoint to ship high-fidelity logs (Sysmon & PowerShell) using Winlogbeat, and then execute a simulated encoded PowerShell attack.

The final objective was to hunt down and identify the "smoking gun" artifacts of this attack using the Kibana interface, demonstrating a complete end-to-end analysis.

---

## 2. Tools & Lab Architecture

This project utilized a "Beat-to-Elasticsearch-to-Kibana" (B-E-K) architecture, bypassing Logstash for a lightweight, efficient pipeline.

| Component | Role | Technology Used |
| :--- | :--- | :--- |
| **SIEM Host** | SIEM & Data Store | Ubuntu Server (VM), Elasticsearch 9.x, Kibana 9.x |
| **Endpoint** | Log Source | Windows 11 VM (VirtualBox) |
| **Logging** | Data Collection | Sysmon, Winlogbeat 9.x |

### Architecture Diagram

[Windows 11 VM (Sysmon, Winlogbeat)] --(Logs via Port 9200)--> [Ubuntu SIEM Host (Elasticsearch, Kibana)] <-- [SOC Analyst (Browser)]


---

## 3. Methodology & Process

### Phase 1: SIEM Host Deployment & Troubleshooting

The first phase involved manually installing and configuring the Elastic Stack on an existing Ubuntu Server. This presented significant, real-world troubleshooting challenges.

**Elasticsearch Installation:**
The initial `systemctl start elasticsearch` command failed due to Elasticsearch's strict startup "bootstrap checks."

* **Fixed `vm.max_map_count`:** Set `vm.max_map_count=262144` in `/etc/sysctl.conf` to allow sufficient memory mapping.
* **Fixed File Descriptors:** Set `LimitNOFILE=65535` and `LimitNPROC=4096` in the systemd override file to allow the service to open enough files and threads.
* **Fixed Cluster Discovery:** The final blocker was a discovery check. This was resolved by setting `cluster.initial_master_nodes: ["node-name"]` in `elasticsearch.yml` to explicitly define the node for a single-node cluster.

**Kibana Installation:**
Kibana was installed and configured to bind to the server's network IP (`server.host: "SIEM_IP"`) and point to the local Elasticsearch instance (`elasticsearch.hosts: ["http://SIEM_IP:9200"]`).

### Phase 2: Endpoint Configuration & Log Shipping

The Windows 11 endpoint was configured to generate and ship high-fidelity logs.

1.  **Sysmon Installation:** Installed Sysmon with a community-standard configuration file to capture detailed process creation events (Event ID 1).
2.  **Winlogbeat Configuration:** Deployed Winlogbeat and customized the `winlogbeat.yml` to collect the most critical logs for threat hunting:
    * `Microsoft-Windows-Sysmon/Operational` (Sysmon Events)
    * `Windows PowerShell` (Event IDs 400, 403, etc.)
    * `Microsoft-Windows-PowerShell/Operational` (Event IDs 4103, 4104 - Script Block Logging)
3.  **Troubleshooting Winlogbeat:**
    * **PowerShell Execution Policy:** Bypassed the `Restricted` policy by setting `Set-ExecutionPolicy Bypass -Scope Process` to allow the `install-service-winlogbeat.ps1` script to run.
    * **Firewall Block:** The final (and most critical) issue was the Windows Defender Firewall on the VM blocking outbound traffic on port 9200. **Temporarily disabling the firewall** confirmed this was the blocker, allowing logs to flow.

### Phase 3: Simulation & Threat Hunting

With the pipeline active, the simulation and hunt could begin.

1.  **Simulation:** On the Windows 11 VM, I executed a simple but suspicious encoded PowerShell command to launch `calc.exe`. This technique is a common way for attackers to hide their payloads.
    ```powershell
    powershell.exe -e VwBhAHoAdQBoACgAYwBhAGwAYwAuAGUAeABlACkA
    ```
    *This action successfully launched the Calculator application, confirming the payload executed.*

2.  **The Hunt:** In Kibana, I began hunting for the artifacts.
    * **Initial Failure:** My initial KQL queries for `process.executable: "*powershell.exe"` and `winlog.event_data.Image: "*powershell.exe"` **failed to return results**, even though I knew the event occurred.
    * **Troubleshooting KQL:** This failure was due to a common indexing issue where Elasticsearch maps fields as `text` (analyzed for full-text search) instead of `keyword` (a single, searchable string), which breaks simple KQL queries.
    * **The Successful Query:** By pivoting my search to the raw `message` field and looking for a unique part of the known Base64 string, I successfully located the event.

    **Final Working Query:**
    ```kql
    message: VwBhAHoAdQBo*
    ```

---

## 4. Analysis & Key Findings

The hunt successfully uncovered two high-value log events that, when correlated, provided a complete picture of the attack.

### Finding 1: The Parent Process (Sysmon Event ID 1)

This is the "smoking gun" artifact. It's a Sysmon Process Create event that shows **`calc.exe`** being launched. The most critical data point is the **Parent Command Line**, which contains the full, encoded payload.

> **[INSERT SCREENSHOT HERE: A screenshot of your successful KQL query `message: "VwBhAHoAdQBo"` in the Kibana Discover tab, showing the resulting log hits.]**

> **[INSERT SCREENSHOT HERE: A screenshot of the expanded Sysmon Event ID 1 log, clearly highlighting the `winlog.event_data.ParentCommandLine` field. Make sure the encoded string is visible.]**

### Finding 2: The Malicious Command (PowerShell Event ID 403)

I also located the PowerShell Engine Lifecycle event, which logs the *start* of the PowerShell engine and explicitly captures the `HostApplication` (the command) that initiated it, including the `-e` flag and the Base64 payload.

> **[INSERT SCREENSHOT HERE: A screenshot of the expanded PowerShell Event ID 403 log, clearly highlighting the `winlog.event_data.param3` field. Make sure the `HostApplication` line is visible.]**

---

## 5. Key Challenges & Lessons Learned

* **Troubleshooting is the Job:** The majority of this project was spent troubleshooting. The Elasticsearch bootstrap checks and the Winlogbeat firewall issue are not "failures" but a critical, realistic part of a security engineer's responsibilities.
* **Indexing is Key:** The failure of my initial KQL queries (`process.executable: "..."`) was a powerful lesson in Elastic indexing. Understanding the difference between `text` and `keyword` fields (and how to bypass the issue by searching the `.keyword` field or the raw `message`) is essential for effective hunting.
* **Parent-Child Analysis is Gold:** The Sysmon Event ID 1 log, with its `ParentCommandLine` field, is the single most valuable artifact for this type of hunt. It directly links the obfuscated command (the "how") to the malicious action (the "what").

---

## 6. Final Project Dashboard

To complete the project, I created a simple visualization in Kibana to show the breakdown of log types coming from my Windows endpoint.

> **[INSERT SCREENSHOT HERE: A screenshot of your final Kibana Dashboard, showing the "P3 - Lo
