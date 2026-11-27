# depweather forecast, 2026-11-27

Vulnerabilities published in the last 7 days for 149 popular open-source packages, generated 2026-11-27T16:37:28Z by https://depweather.com from OSV, CISA KEV, FIRST EPSS and NVD data. Severity comes from the upstream advisory.

## Numbers

- Popular packages with a new advisory this week: 10 of 149
- Added to the CISA Known Exploited Vulnerabilities catalog this week (all vendors): 19
- New CVEs in NVD today (UTC): 302
- CVEs published in 2026-11 so far: 15,340 (same month last year: 3,021)

## By ecosystem

### Packagist

- **Drupal core (drupal/core)**: 2 advisories, worst actively exploited (CISA KEV); fixed in 10.6.23, 11.3.23, 11.4.14, 10.6.22 and more. Example: [DRUPAL-CORE-2026-017](https://osv.dev/vulnerability/DRUPAL-CORE-2026-017) ***Update:** the Security Team has received a report this was exploited on live sites as early as 2026-11-19 19:00 UTC.*

### Runtimes & servers

- **PHP**: 17 advisories, worst critical; fixed in 8.2.36, 8.3.37, 8.4.28, 8.5.13. Example: [BIT-libphp-2026-129496](https://osv.dev/vulnerability/BIT-libphp-2026-129496) Timezone cache use-after-free can lead to remote code execution
- **Tomcat**: 16 advisories, worst critical; fixed in 9.0.124, 10.1.62, 11.0.29, 9.0.116 and more. Example: [BIT-tomcat-2026-95517](https://osv.dev/vulnerability/BIT-tomcat-2026-95517) Apache Tomcat: Multiple vulnerabilities in EncryptInterceptor
- **nginx**: 7 advisories, worst critical; fixed in 1.30.7, 1.31.9. Example: [BIT-nginx-2026-123634](https://osv.dev/vulnerability/BIT-nginx-2026-123634) NGINX resolver vulnerability
- **Java (OpenJDK) (java)**: 51 advisories, worst high; fixed in 1.8.0, 8.0.511, 11.0.33, 17.0.21 and more. Example: [BIT-java-2026-91484](https://osv.dev/vulnerability/BIT-java-2026-91484) Vulnerability in Oracle Java SE (component: Java plugin).  Supported versions that are affected are Oracle Java SE: 8u503 and  8u503-perf. Difficult to exploit vulnerability allows low privileged attacker with logon to the infrastructure where Oracle Java SE executes to compromise Oracle Java SE.  W
- **Node.js (node)**: 15 advisories, worst high; fixed in 24.22.3, 26.13.1, 22.23.5. Example: [BIT-node-2026-126051](https://osv.dev/vulnerability/BIT-node-2026-126051) Node.js is vulnerable to a remotely triggerable uncaught exception in TLS servers via deferred handshake callbacks
- **Apache httpd (apache)**: 2 advisories, worst high; fixed in 2.4.71. Example: [BIT-apache-2026-106023](https://osv.dev/vulnerability/BIT-apache-2026-106023) Apache HTTP Server: mod_md NULL pointer dereference leads to child process crash
- **Ruby**: 1 advisory, worst high; fixed in 3.3.14, 3.4.13, 4.0.10. Example: [BIT-ruby-2026-132825](https://osv.dev/vulnerability/BIT-ruby-2026-132825) Ruby before 3.3.14, 3.4.13, and 4.0.10 has a heap-based buffer overflow during case conversion. One byte can be written outside a buffer for, for example, ISO-8859-1 or Windows-1252.
- **Python**: 5 advisories, worst medium; fixed in 3.16.0. Example: [BIT-libpython-2026-124249](https://osv.dev/vulnerability/BIT-libpython-2026-124249) `http.cookiejar` applies expired `Set-Cookie` to cookie store before policy validation

### Hex

- **Phoenix**: 2 advisories, worst high; fixed in 1.5.16, 1.6.18, 1.7.25, 1.8.17. Example: [EEF-CVE-2026-128361](https://osv.dev/vulnerability/EEF-CVE-2026-128361) Unsanitized presence key crashes Presence tracker

### npm

No new advisories for the tracked packages.

### PyPI

No new advisories for the tracked packages.

### Maven

No new advisories for the tracked packages.

### NuGet

No new advisories for the tracked packages.

### crates.io

No new advisories for the tracked packages.

### Go

No new advisories for the tracked packages.

### RubyGems

No new advisories for the tracked packages.

## Added to CISA KEV this week (all vendors)

- 2026-11-25: CVE-2026-103406, Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router: Hewlett Packard Enterprise (HPE) Juniper Session Smart Conductor and Session Smart Router OS Command Injection Vulnerability
- 2026-11-25: CVE-2026-133469, Vates Xen Orchestra: Vates Xen Orchestra Improper Validation of Specified Type of Input Vulnerability
- 2026-11-25: CVE-2025-41450, Danfoss AK-SM 800A Series: Danfoss AK-SM 800A Series Improper Authentication Vulnerability
- 2026-11-25: CVE-2023-25914, Danfoss AK-SM 800A Series: Danfoss AK-SM 800A Series Path Traversal Vulnerability
- 2026-11-25: CVE-2023-25915, Danfoss AK-SM 800A Series: Danfoss AK-SM 800A Series Improper Input Validation Vulnerability
- 2026-11-25: CVE-2026-133324, Mitel MiCollab: Mitel MiCollab Not Failing Securely Vulnerability
- 2026-11-25: CVE-2026-133275, Mitel MiCollab: Mitel MiCollab Unrestricted Upload of File with Dangerous Type Vulnerability
- 2026-11-25: CVE-2026-133311, Mitel MiCollab: Mitel MiCollab Weak Authentication Vulnerability
- 2026-11-25: CVE-2026-133303, Mitel MiCollab: Mitel MiCollab XML Injection Vulnerability
- 2026-11-25: CVE-2026-133323, Mitel MiCollab: Mitel MiCollab OS Command Injection Vulnerability
- 2026-11-24: CVE-2026-132224, Optimizely Web Experimentation: Optimizely Web Experimentation External Control of Critical State Data Vulnerability
- 2026-11-24: CVE-2026-131914, Idunno AntiCsrf: Idunno AntiCsrf Deserialization of Untrusted Data Vulnerability
- 2026-11-24: CVE-2026-132165, Drupal Core: Drupal Core Remote Code Execution Vulnerability
- 2026-11-23: CVE-2026-133968, Project MONAI MONAI Label: Project MONAI MONAI Label Path Traversal Vulnerability
- 2026-11-23: CVE-2026-134624, N-able MailAssure: N-able MailAssure (SpamExperts) Server-Side Request Forgery (SSRF) Vulnerability
- 2026-11-20: CVE-2026-129448, Apache Roller: Apache Roller Deserialization of Untrusted Data Vulnerability
- 2026-11-20: CVE-2026-123890, Broadcom VMware vCenter: VMWare vCenter Authentication Bypass Using an Alternate Path or Channel Vulnerability
- 2026-11-20: CVE-2025-42884, SAP NetWeaver: SAP NetWeaver Improper Neutralization of Special Elements in Data Query Logic Vulnerability
- 2026-11-20: CVE-2026-76466, Cisco Expressway Series: Cisco Expressway Series Use of Hard-coded Credentials Vulnerability

Full data: https://depweather.com/data/latest.json
