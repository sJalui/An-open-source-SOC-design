# Open‑Source SOC: Wazuh + Suricata/Zeek + TheHive/Cortex + MISP + Shuffle

A modular, fully open‑source SOC blueprint that unifies endpoint telemetry, network detection, incident response, threat intelligence, and automation using Wazuh, Suricata, Zeek, TheHive, Cortex, MISP, Elasticsearch/Kibana, and Shuffle for end‑to‑end detection and response.

## Diagrams

### Wazuh End‑to‑End Telemetry and Alert Pipeline
![Wazuh End‑to‑End Telemetry and Alert Pipeline](https://github.com/sJalui/An-open-source-SOC-design/blob/main/Images/wazuh_end-to-end%20telemetry%20and%20alert%20pipeline.png?raw=true)

### High‑Level Architecture
![High‑Level Architecture](https://github.com/sJalui/An-open-source-SOC-design/blob/main/Images/block_high_level_architecture.png?raw=true)

### End‑to‑End Alert Flow
![End‑to‑End Sequence](https://github.com/sJalui/An-open-source-SOC-design/blob/main/Images/end_to_end_seq.png?raw=true)

### Full Workflow Sequence
![Full Workflow Sequence](https://github.com/sJalui/An-open-source-SOC-design/blob/main/Images/full%20workflow%20sequence.png?raw=true")

### MISP Threat‑Intel Ecosystem
![MISP Threat‑Intel Ecosystem](https://github.com/sJalui/An-open-source-SOC-design/blob/main/Images/misp_threat_intelligence_ecosystem.png?raw=true)

## Short explanation

This project demonstrates an opinionated open‑source SOC where Wazuh provides SIEM/XDR telemetry and detections, Suricata and Zeek add network‑level alerts and rich context, and TheHive/Cortex/MISP deliver case‑centric investigations with automated enrichment and IOC sharing, all orchestrated by Shuffle for rapid, repeatable response.

## Architecture overview

- Sensors: Wazuh agents on endpoints plus Suricata NIDS and Zeek NSM sensors on taps/SPAN ports to observe ingress, egress, and key east‑west traffic for correlation with host activity.
- Forwarders: Wazuh Manager’s built‑in Filebeat ships alerts and archives while Filebeat modules on sensor hosts ship Suricata EVE JSON and Zeek logs into Elasticsearch for search and dashboards.
- Storage/UI: Elasticsearch (Wazuh Indexer) stores events for Kibana and for Wazuh’s correlation engine to generate alerts and drive investigations in TheHive.
- Response/Intel: TheHive manages cases and tasks, Cortex enriches observables at scale, MISP correlates and shares IOCs, and Shuffle automates triage, enrichment, and containment via device APIs.

## Core components

- Wazuh (SIEM/XDR): Host log collection, FIM, vulnerability/compliance checks, rules‑based detections, and active responses with TLS‑secured shipping to the indexer and a REST API for integrations.
- Suricata (NIDS): Signature‑based detections emitted as EVE JSON for Filebeat/Wazuh ingestion and Kibana dashboards to surface known network threats.
- Zeek (NSM): Protocol‑rich metadata (conn, dns, http, tls, notice) enabling behavioral pivots and context around Suricata hits and endpoint events.
- TheHive (SIRP): Collaborative case and alert management with templates, tasks, and audit logs, ingesting from SIEM and MISP while exposing observables to enrichment engines.
- Cortex (Enrichment): Analyzer framework that scores and contextualizes IPs, domains, hashes, and URLs from TheHive or playbooks at scale.
- MISP (TIP): IOC repository and sharing hub feeding alerts to TheHive and correlation back into the SOC, with two‑way updates from investigations.
- Shuffle (SOAR): Visual workflows that create cases, run analyzers, notify, and execute blocks or quarantines through APIs to reduce mean‑time‑to‑response.

## Data flow (alert lifecycle)

1. Collection: Wazuh agents ship endpoint logs and alerts, while Filebeat modules ship Suricata EVE and Zeek logs to Elasticsearch for unified search and dashboards.
2. Detection: Wazuh rules, Suricata signatures, and Zeek notices generate alerts that can be forwarded to TheHive and queued to trigger SOAR playbooks.
3. Case creation: Shuffle receives alert webhooks and opens TheHive cases with tasks and observables for structured triage and collaboration.
4. Enrichment: TheHive invokes Cortex analyzers and queries MISP so results flow back into the case timeline and tags, accelerating investigations.
5. Response: Shuffle playbooks perform notifications and containment (e.g., firewall blocks) and update case status, while metrics surface in Kibana for oversight.

## Getting started (minimal path)

- Deploy Wazuh Manager/Indexer/Dashboard and enroll sample Windows/Linux endpoints to validate alert indexing and dashboards in Kibana.
- Add a Suricata and a Zeek sensor on a SPAN/tap, enable Filebeat Suricata/Zeek modules, and confirm EVE/Zeek indices and saved searches in Kibana.
- Stand up TheHive and Cortex, configure connectors and API keys, and run a few enrichments from a test case to verify integration.
- Install MISP and connect to TheHive to pull feed‑backed alerts and push validated IOCs from cases for correlation and sharing.
- Install Shuffle and build a webhook‑triggered playbook that creates a case, runs Cortex, posts notifications, and optionally blocks an IP via a firewall/API.

## License

Licensed under MIT.
