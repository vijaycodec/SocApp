# Comprehensive Control Mappings to ISO 27001:2022 Annex A Controls

## Research Summary

This document provides comprehensive control mappings from major cybersecurity and compliance frameworks to ISO 27001:2022 Annex A controls. The research was conducted on November 13, 2025, using authoritative sources including NIST OLIR mappings, AICPA documentation, BSI Group whitepapers, and industry compliance resources.

**Important Note:** Control mappings are not always one-to-one relationships. The mappings provided indicate where controls address similar security objectives but may require additional implementation details to achieve full equivalency.

---

## Table of Contents

1. [ISO 27001:2022 Annex A Structure](#iso-270012022-annex-a-structure)
2. [NIST 800-53 Rev 5 to ISO 27001:2022](#1-nist-800-53-rev-5-to-iso-270012022)
3. [PCI DSS v4.0 to ISO 27001:2022](#2-pci-dss-v40-to-iso-270012022)
4. [HIPAA Security Rule to ISO 27001:2022](#3-hipaa-security-rule-to-iso-270012022)
5. [SOC 2 TSC to ISO 27001:2022](#4-soc-2-tsc-to-iso-270012022)
6. [GDPR to ISO 27001:2022](#5-gdpr-to-iso-270012022)
7. [Key Findings and Recommendations](#key-findings-and-recommendations)
8. [Authoritative Sources](#authoritative-sources)

---

## ISO 27001:2022 Annex A Structure

ISO 27001:2022 contains **93 controls** organized into 4 main categories:

### Organizational Controls (A.5.1 – A.5.37)
37 controls covering policies, risk management, asset management, supplier security, and incident management.

### People Controls (A.6.1 – A.6.8)
8 controls covering screening, terms and conditions, awareness training, and disciplinary processes.

### Physical Controls (A.7.1 – A.7.14)
14 controls covering physical security, secure areas, equipment security, and environmental protection.

### Technological Controls (A.8.1 – A.8.34)
34 controls covering access control, cryptography, network security, logging, and vulnerability management.

**Key Changes from 2013 to 2022:**
- Reduced from 114 controls to 93 controls
- Reorganized from 14 categories to 4 themes
- Added 11 new controls including threat intelligence (A.5.7), cloud security (A.5.23), secure coding (A.8.28), and configuration management (A.8.9)

---

## 1. NIST 800-53 Rev 5 to ISO 27001:2022

**Source:** NIST Computer Security Resource Center (CSRC) - OLIR (Online Informative References) Program

### Official Mapping Document
NIST provides an official crosswalk between SP 800-53 Rev. 5 and ISO/IEC 27001:2022 through the OLIR system.
- **Access Point:** https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155
- **Format:** Available through NIST CSRC supplemental materials for SP 800-53 Rev. 5

### Key Control Mappings

| NIST 800-53 Rev 5 | ISO 27001:2022 Controls | Description |
|-------------------|------------------------|-------------|
| **AC-1** | 5.2, 5.3, 7.5.1, 7.5.2, 7.5.3, A.5.1, A.5.2, A.5.4, A.5.15, A.5.31, A.5.36, A.5.37 | Access Control Policy and Procedures - Establishes organizational access control policies |
| **AC-2** | A.5.16, A.5.18, A.8.2 | Account Management - User account provisioning and lifecycle management |
| **AC-3** | A.5.15, A.5.33*, A.8.3, A.8.4*, A.8.18, A.8.20, A.8.26 | Access Enforcement - Enforces approved authorizations for logical access |
| **AC-4** | A.8.20, A.8.22 | Information Flow Enforcement - Controls information flows within systems |
| **AC-5** | A.5.15, A.8.2, A.8.3 | Separation of Duties - Divides duties among individuals to reduce risk |
| **AC-6** | A.5.15, A.5.18, A.8.2, A.8.3 | Least Privilege - Employs principle of least privilege |
| **AC-7** | A.8.5 | Unsuccessful Logon Attempts - Enforces limit on consecutive invalid access attempts |
| **AC-11** | A.8.5 | Session Lock - Prevents further access by initiating session lock |
| **AC-12** | A.8.5 | Session Termination - Automatically terminates user sessions |
| **AC-17** | A.5.14, A.6.7, A.8.5 | Remote Access - Authorizes, monitors, and controls remote access |
| **AC-18** | A.8.20, A.8.21 | Wireless Access - Controls wireless access to the system |
| **AC-19** | A.6.7, A.8.1 | Access Control for Mobile Devices - Establishes usage restrictions for mobile devices |
| **AC-20** | A.5.19, A.5.20, A.5.21 | Use of External Information Systems - Establishes terms for authorized external access |
| **AT-1** | A.6.3 | Security Awareness and Training Policy - Develops awareness and training policy |
| **AT-2** | A.6.3 | Security Awareness Training - Provides basic security awareness training |
| **AT-3** | A.6.3 | Role-Based Security Training - Provides role-based security training |
| **AU-1** | A.5.1, A.8.15 | Audit and Accountability Policy - Develops audit policy and procedures |
| **AU-2** | A.8.15 | Event Logging - Determines auditable events |
| **AU-3** | A.8.15 | Content of Audit Records - Ensures audit records contain information to establish what, when, where, source, outcome |
| **AU-6** | A.8.15, A.8.16 | Audit Review, Analysis, and Reporting - Reviews and analyzes audit records |
| **AU-9** | A.8.15 | Protection of Audit Information - Protects audit information from unauthorized access |
| **AU-12** | A.8.15 | Audit Generation - Provides audit record generation capability |
| **CA-1** | A.5.1 | Security Assessment and Authorization Policy - Develops assessment policy |
| **CA-2** | A.5.8, A.5.9 | Security Assessments - Develops security assessment plan |
| **CA-3** | A.5.19, A.5.20, A.5.21 | System Interconnections - Authorizes connections from system to other systems |
| **CA-5** | A.5.8 | Plan of Action and Milestones - Develops plan to correct weaknesses |
| **CA-6** | A.5.8 | Security Authorization - Assigns senior official as authorizing official |
| **CA-7** | A.5.8, A.8.8 | Continuous Monitoring - Develops continuous monitoring strategy |
| **CM-1** | A.5.1, A.8.9 | Configuration Management Policy - Develops configuration management policy |
| **CM-2** | A.8.9 | Baseline Configuration - Develops and maintains baseline configurations |
| **CM-3** | A.8.9, A.8.32 | Configuration Change Control - Determines types of changes that are configuration-controlled |
| **CM-4** | A.8.15, A.8.16 | Security Impact Analysis - Analyzes changes to determine security impacts |
| **CM-6** | A.8.9 | Configuration Settings - Establishes and documents mandatory configuration settings |
| **CM-7** | A.8.9 | Least Functionality - Configures system to provide only essential capabilities |
| **CM-8** | A.5.9 | Information System Component Inventory - Develops and maintains inventory |
| **CP-1** | A.5.1, A.5.29, A.5.30 | Contingency Planning Policy - Develops contingency planning policy |
| **CP-2** | A.5.29, A.5.30 | Contingency Plan - Develops contingency plan for the system |
| **CP-4** | A.5.30 | Contingency Plan Testing - Tests contingency plan at planned intervals |
| **CP-6** | A.7.13 | Alternate Storage Site - Establishes alternate storage site |
| **CP-7** | A.5.30 | Alternate Processing Site - Establishes alternate processing site |
| **CP-9** | A.8.13 | Information System Backup - Conducts backups of user and system-level information |
| **CP-10** | A.5.30 | Information System Recovery and Reconstitution - Provides for recovery of system |
| **IA-1** | A.5.1 | Identification and Authentication Policy - Develops identification and authentication policy |
| **IA-2** | A.8.5 | Identification and Authentication - Uniquely identifies and authenticates users |
| **IA-3** | A.8.5 | Device Identification and Authentication - Uniquely identifies and authenticates devices |
| **IA-4** | A.5.16, A.5.17, A.5.18 | Identifier Management - Manages information system identifiers |
| **IA-5** | A.8.5 | Authenticator Management - Manages information system authenticators |
| **IA-6** | A.8.5 | Authenticator Feedback - Obscures feedback of authentication information |
| **IA-8** | A.5.16, A.8.5 | Identification and Authentication (Non-Organizational Users) - Uniquely identifies non-organizational users |
| **IR-1** | A.5.1, A.5.24 | Incident Response Policy - Develops incident response policy |
| **IR-2** | A.6.3, A.6.8 | Incident Response Training - Provides training to system users |
| **IR-4** | A.5.24, A.5.25, A.5.26 | Incident Handling - Implements incident handling capability |
| **IR-5** | A.5.6, A.8.16 | Incident Monitoring - Tracks and documents information security incidents |
| **IR-6** | A.5.6, A.5.26 | Incident Reporting - Requires personnel to report suspected incidents |
| **IR-7** | A.5.26 | Incident Response Assistance - Provides incident response support |
| **IR-8** | A.5.24, A.5.27 | Incident Response Plan - Develops and implements incident response plan |
| **MA-1** | A.5.1 | System Maintenance Policy - Develops maintenance policy |
| **MA-2** | A.7.7, A.8.14 | Controlled Maintenance - Schedules, performs, and documents maintenance |
| **MA-4** | A.7.7 | Nonlocal Maintenance - Approves and monitors nonlocal maintenance |
| **MA-5** | A.7.7 | Maintenance Personnel - Establishes process for maintenance personnel authorization |
| **MP-1** | A.5.1 | Media Protection Policy - Develops media protection policy |
| **MP-2** | A.7.10 | Media Access - Restricts access to information on digital and non-digital media |
| **MP-3** | A.8.10 | Media Marking - Marks information indicating distribution limitations |
| **MP-4** | A.7.8, A.8.11 | Media Storage - Physically controls and securely stores digital media |
| **MP-5** | A.7.8 | Media Transport - Protects and controls digital media during transport |
| **MP-6** | A.8.10, A.8.11 | Media Sanitization - Sanitizes media before disposal or reuse |
| **MP-7** | A.7.10 | Media Use - Restricts or prohibits use of types of media |
| **PE-1** | A.5.1 | Physical and Environmental Protection Policy - Develops physical security policy |
| **PE-2** | A.7.1, A.7.2 | Physical Access Authorizations - Develops and maintains list of authorized personnel |
| **PE-3** | A.7.1, A.7.2, A.7.3 | Physical Access Control - Enforces physical access authorizations |
| **PE-4** | A.7.1, A.7.4 | Access Control for Transmission Medium - Controls physical access to transmission lines |
| **PE-5** | A.7.2, A.7.3 | Access Control for Output Devices - Controls physical access to output devices |
| **PE-6** | A.7.4 | Monitoring Physical Access - Monitors physical access to facility |
| **PE-8** | A.7.4 | Visitor Access Records - Maintains visitor access records |
| **PE-12** | A.7.9 | Emergency Lighting - Employs and maintains automatic emergency lighting |
| **PE-13** | A.7.9 | Fire Protection - Employs and maintains fire suppression and detection |
| **PE-14** | A.7.9 | Temperature and Humidity Controls - Maintains temperature and humidity levels |
| **PE-15** | A.7.9 | Water Damage Protection - Protects system from damage from water leakage |
| **PE-16** | A.7.10 | Delivery and Removal - Authorizes, monitors, and controls entering and exiting items |
| **PL-1** | A.5.1 | Security Planning Policy - Develops security planning policy |
| **PL-2** | A.5.1, A.5.2 | System Security Plan - Develops security plan for the system |
| **PL-4** | A.5.1 | Rules of Behavior - Establishes and makes readily available rules describing responsibilities |
| **PS-1** | A.5.1 | Personnel Security Policy - Develops personnel security policy |
| **PS-2** | A.6.1 | Position Risk Designation - Assigns risk designation to all positions |
| **PS-3** | A.6.1 | Personnel Screening - Screens individuals prior to authorizing access |
| **PS-4** | A.6.2, A.6.4 | Personnel Termination - Terminates access upon termination of employment |
| **PS-5** | A.6.4 | Personnel Transfer - Reviews and confirms access authorizations during transfers |
| **PS-6** | A.6.2, A.6.6 | Access Agreements - Completes appropriate access agreements |
| **PS-7** | A.6.5, A.6.6 | Third-Party Personnel Security - Establishes requirements for third-party providers |
| **PS-8** | A.6.4 | Personnel Sanctions - Employs formal sanctions process for failing to comply |
| **RA-1** | A.5.1 | Risk Assessment Policy - Develops risk assessment policy |
| **RA-2** | A.6.1 | Security Categorization - Categorizes information and system |
| **RA-3** | A.5.8 | Risk Assessment - Conducts assessment of risk |
| **RA-5** | A.8.8 | Vulnerability Scanning - Scans for vulnerabilities in system |
| **SA-1** | A.5.1 | System and Services Acquisition Policy - Develops acquisition policy |
| **SA-2** | A.5.10 | Allocation of Resources - Determines security requirements for system |
| **SA-3** | A.8.25, A.8.27 | System Development Life Cycle - Manages system using SDLC |
| **SA-4** | A.5.19, A.5.20, A.5.21, A.5.22 | Acquisition Process - Includes security requirements in acquisition contracts |
| **SA-5** | A.8.25, A.8.27 | Information System Documentation - Obtains administrator and user documentation |
| **SA-8** | A.5.1 | Security Engineering Principles - Applies information security engineering principles |
| **SA-9** | A.5.19, A.5.20, A.5.21, A.5.22 | External Information System Services - Requires providers to comply with requirements |
| **SA-10** | A.8.25, A.8.27 | Developer Configuration Management - Requires developer to perform configuration management |
| **SA-11** | A.8.25, A.8.27, A.8.29 | Developer Security Testing - Requires developer to create and execute security test plan |
| **SA-15** | A.8.27, A.8.29 | Development Process, Standards, and Tools - Requires developer to follow development process |
| **SC-1** | A.5.1 | System and Communications Protection Policy - Develops protection policy |
| **SC-2** | A.8.1 | Application Partitioning - Separates user functionality from system management |
| **SC-4** | A.8.11, A.8.24 | Information in Shared Resources - Prevents unauthorized information transfer |
| **SC-5** | A.8.20 | Denial of Service Protection - Protects against denial of service attacks |
| **SC-7** | A.8.20, A.8.21, A.8.22 | Boundary Protection - Monitors and controls communications at external boundaries |
| **SC-8** | A.8.24 | Transmission Confidentiality and Integrity - Protects confidentiality and integrity of transmitted information |
| **SC-10** | A.8.5 | Network Disconnect - Terminates network connection after defined period |
| **SC-12** | A.8.24 | Cryptographic Key Establishment and Management - Establishes and manages cryptographic keys |
| **SC-13** | A.8.24 | Cryptographic Protection - Implements required cryptography |
| **SC-17** | A.8.6 | Public Key Infrastructure Certificates - Issues public key certificates |
| **SC-20** | A.8.23 | Secure Name/Address Resolution - Provides additional data origin authentication |
| **SC-21** | A.8.23 | Secure Name/Address Resolution (Recursive/Caching) - Requests and performs data origin authentication |
| **SC-22** | A.8.16, A.8.23 | Architecture and Provisioning for Name/Address Resolution - Ensures systems are fault-tolerant and implement role separation |
| **SC-28** | A.8.11, A.8.24 | Protection of Information at Rest - Protects confidentiality and integrity of information at rest |
| **SI-1** | A.5.1 | System and Information Integrity Policy - Develops integrity policy |
| **SI-2** | A.8.8 | Flaw Remediation - Identifies, reports, and corrects flaws |
| **SI-3** | A.8.7 | Malicious Code Protection - Implements malicious code protection |
| **SI-4** | A.8.15, A.8.16 | Information System Monitoring - Monitors system to detect attacks and unauthorized activity |
| **SI-5** | A.5.7, A.8.16 | Security Alerts, Advisories, and Directives - Receives security alerts and advisories |
| **SI-7** | A.8.16 | Software, Firmware, and Information Integrity - Employs integrity verification tools |
| **SI-10** | A.8.3 | Information Input Validation - Checks validity of information inputs |
| **SI-11** | A.8.16 | Error Handling - Generates error messages that provide necessary information |
| **SI-12** | A.8.16 | Information Handling and Retention - Handles and retains information according to requirements |

**Note:** Asterisk (*) indicates ISO/IEC control does not fully satisfy the intent of the NIST control

### Important Considerations

1. **Non-One-to-One Relationships:** Many NIST controls map to multiple ISO controls and vice versa
2. **Scope Differences:** NIST 800-53 is designed for federal information systems; ISO 27001 is a general ISMS framework
3. **Implementation Guidance:** ISO 27002:2022 provides detailed implementation guidance for ISO 27001 controls
4. **Complementary Use:** Organizations can use both frameworks together, with ISO 27001 providing the ISMS structure and NIST controls providing detailed technical requirements

---

## 2. PCI DSS v4.0 to ISO 27001:2022

**Source:** Industry mapping documents, ISMS.online, IJSR research, compliance platforms

### Framework Overview

**PCI DSS 4.0** (Released March 31, 2022; Mandatory April 1, 2024)
- 12 high-level requirements
- 6 overarching goals
- Focused on protecting payment card data
- Rule-based compliance standard

**Coverage Analysis:** Only 25.7% of PCI DSS requirements map directly to related ISO 27001 controls, leaving a 74.3% gap. Organizations need both frameworks for comprehensive payment card security.

### The 12 PCI DSS Requirements

**Goal 1: Build and Maintain a Secure Network and Systems**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 1:** Install and Maintain Network Security Controls | A.8.20, A.8.21, A.8.22, A.5.14 | Network Security Controls (firewalls, routers) configured and managed; access to CDE restricted; connections between networks controlled |
| **Requirement 2:** Apply Secure Configurations to All System Components | A.8.9, A.8.18, A.5.23 | Secure configurations applied; vendor defaults changed; system components securely configured and managed |

**Goal 2: Protect Account Data**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 3:** Protect Stored Account Data | A.8.11, A.8.24, A.8.10 | Cardholder data secured through encryption; data retention policies; secure deletion |
| **Requirement 4:** Protect Cardholder Data with Strong Cryptography During Transmission | A.8.24, A.8.23 | Strong cryptography for transmission over open, public networks; TLS/SSL implementation |

**Goal 3: Maintain a Vulnerability Management Program**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 5:** Protect All Systems and Networks from Malicious Software | A.8.7 | Anti-malware solutions deployed and maintained; malicious code protection |
| **Requirement 6:** Develop and Maintain Secure Systems and Software | A.8.8, A.8.25, A.8.27, A.8.28, A.8.29 | Vulnerabilities addressed; secure software development practices; security testing; secure coding |

**Goal 4: Implement Strong Access Control Measures**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 7:** Restrict Access to System Components and Cardholder Data by Business Need to Know | A.5.15, A.8.2, A.8.3 | Access controls based on need-to-know; least privilege principle |
| **Requirement 8:** Identify Users and Authenticate Access to System Components | A.8.5, A.5.16, A.5.17, A.5.18 | Multi-factor authentication (MFA); passwords minimum 12 characters; unique user identification |

**Goal 5: Regularly Monitor and Test Networks**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 9:** Restrict Physical Access to Cardholder Data | A.7.1, A.7.2, A.7.3, A.7.4 | Physical access controls; visitor management; media destruction |
| **Requirement 10:** Log and Monitor All Access to System Components and Cardholder Data | A.8.15, A.8.16 | Automated audit log reviews; SIEM solutions; logging of all access |
| **Requirement 11:** Test Security of Systems and Networks Regularly | A.8.8, A.5.8 | Vulnerability scans; penetration testing; security testing |

**Goal 6: Maintain an Information Security Policy**

| PCI DSS Requirement | ISO 27001:2022 Controls | Description |
|---------------------|------------------------|-------------|
| **Requirement 12:** Support Information Security with Organizational Policies and Programs | A.5.1, A.5.2, A.5.3, A.6.3, A.5.8 | Security policies; risk assessments; security awareness training (reviewed every 12 months) |

### Detailed Control Mappings (Example Requirements)

| PCI DSS Control | ISO 27001:2022 | Description |
|-----------------|----------------|-------------|
| 1.1.1 - Firewall configuration standards | A.8.20, A.8.21 | Networks security; Security of network services |
| 1.2.1 - Configuration standards for NSCs | A.8.9, A.8.20 | Configuration management; Networks security |
| 2.2.1 - Configuration standards for servers | A.8.9, A.8.18 | Configuration management; Use of privileged utility programs |
| 2.2.2 - Vendor default accounts | A.8.2, A.8.5 | Privileged access rights; Secure authentication |
| 3.5.1 - Disk encryption | A.8.11, A.8.24 | Data masking; Cryptography |
| 3.6.1 - Cryptographic key procedures | A.8.24 | Cryptography (key management) |
| 4.2.1 - Strong cryptography for transmission | A.8.24 | Cryptography (encryption in transit) |
| 5.2.1 - Anti-malware deployment | A.8.7 | Protection against malware |
| 6.2.2 - Inventory of software | A.5.9, A.8.9 | Inventory of information and assets; Configuration management |
| 6.2.3 - Bespoke and custom software | A.8.25, A.8.28 | Secure development life cycle; Secure coding |
| 6.3.2 - Secure coding review | A.8.28, A.8.29 | Secure coding; Security testing in development |
| 7.2.1 - Access control based on job function | A.5.15, A.8.2 | Access control; Privileged access rights |
| 8.3.1 - Multi-factor authentication (MFA) | A.8.5 | Secure authentication |
| 8.3.6 - Password complexity and strength | A.8.5 | Secure authentication (minimum 12 characters) |
| 9.1.1 - Physical access controls | A.7.1, A.7.2 | Physical security perimeters; Physical entry |
| 9.4.4 - Media destruction | A.8.10, A.7.10 | Information deletion; Clear desk and clear screen |
| 10.2.1 - Audit logs implementation | A.8.15 | Logging |
| 10.3.2 - Automated log reviews | A.8.16 | Monitoring activities |
| 11.3.1 - External penetration testing | A.8.8 | Technical vulnerability management |
| 11.3.2 - Internal penetration testing | A.8.8 | Technical vulnerability management |
| 12.1.1 - Security policy establishment | A.5.1 | Policies for information security |
| 12.2.1 - Risk assessment methodology | A.5.8 | Information security risk assessment |
| 12.6.1 - Security awareness program | A.6.3 | Information security awareness, education and training |

### Key Differences

1. **Approach:** PCI DSS is prescriptive and rule-based; ISO 27001 is risk-based and flexible
2. **Scope:** PCI DSS focuses on cardholder data environment (CDE); ISO 27001 covers all organizational information
3. **Certification:** PCI DSS requires annual validation by QSA; ISO 27001 requires certification by accredited body
4. **Flexibility:** ISO 27001 allows organizations to select applicable controls; PCI DSS requires all applicable requirements

---

## 3. HIPAA Security Rule to ISO 27001:2022

**Source:** BSI Group, Pivot Point Security, compliance mapping resources

### Framework Overview

**HIPAA Security Rule** (45 CFR Part 164, Subparts A and C)
- 3 safeguard categories: Administrative, Physical, Technical
- Protects Electronic Protected Health Information (ePHI)
- Flexible, scalable, and technology-neutral
- Contains Required (R) and Addressable (A) specifications

**Coverage Analysis:** At least 47 of ISO 27001's 93 controls can be leveraged to comply with HIPAA requirements. ISO 27799 (health informatics standard) provides additional guidance.

### Administrative Safeguards (§164.308)

| HIPAA Requirement | ISO 27001:2022 Controls | Implementation | Description |
|-------------------|------------------------|----------------|-------------|
| **164.308(a)(1)(i)** - Security Management Process | A.5.1, A.5.8, A.5.10 | Required | Risk analysis, risk management, sanction policy, information system activity review |
| **164.308(a)(1)(ii)(A)** - Risk Analysis | A.5.8 | Required | Conduct accurate and thorough assessment of potential risks to ePHI |
| **164.308(a)(1)(ii)(B)** - Risk Management | A.5.8 | Required | Implement security measures to reduce risks to reasonable and appropriate level |
| **164.308(a)(1)(ii)(C)** - Sanction Policy | A.6.8, A.7.3 | Required | Apply appropriate sanctions against workforce members who fail to comply |
| **164.308(a)(1)(ii)(D)** - Information System Activity Review | A.8.15, A.8.16 | Required | Regularly review records of information system activity |
| **164.308(a)(2)** - Assigned Security Responsibility | A.5.3, A.5.4 | Required | Identify security official responsible for developing and implementing policies |
| **164.308(a)(3)(i)** - Workforce Security | A.6.1, A.6.2, A.6.4 | Required | Ensure workforce members have appropriate access to ePHI |
| **164.308(a)(3)(ii)(A)** - Authorization and/or Supervision | A.5.15, A.6.2 | Addressable | Implement procedures for authorization and supervision of workforce |
| **164.308(a)(3)(ii)(B)** - Workforce Clearance Procedure | A.6.1 | Addressable | Determine access to ePHI is appropriate based on screening procedures |
| **164.308(a)(3)(ii)(C)** - Termination Procedures | A.6.4 | Addressable | Terminate access to ePHI when employment ends or as required |
| **164.308(a)(4)(i)** - Information Access Management | A.5.15, A.8.2, A.8.3 | Required | Authorize access to ePHI consistent with role |
| **164.308(a)(4)(ii)(A)** - Isolating Healthcare Clearinghouse Function | A.8.20, A.8.22 | Required | If clearinghouse, implement policies to protect ePHI from unauthorized access |
| **164.308(a)(4)(ii)(B)** - Access Authorization | A.5.15, A.5.18, A.8.2 | Addressable | Implement policies for granting access to ePHI |
| **164.308(a)(4)(ii)(C)** - Access Establishment and Modification | A.5.16, A.5.18, A.8.2 | Addressable | Implement procedures for establishing, reviewing, and modifying access |
| **164.308(a)(5)(i)** - Security Awareness and Training | A.6.3 | Required | Implement security awareness and training program for all workforce members |
| **164.308(a)(5)(ii)(A)** - Security Reminders | A.6.3 | Addressable | Periodic security updates |
| **164.308(a)(5)(ii)(B)** - Protection from Malicious Software | A.6.3, A.8.7 | Addressable | Procedures for guarding against malware |
| **164.308(a)(5)(ii)(C)** - Log-in Monitoring | A.8.15 | Addressable | Procedures for monitoring log-in attempts and reporting discrepancies |
| **164.308(a)(5)(ii)(D)** - Password Management | A.8.5 | Addressable | Procedures for creating, changing, and safeguarding passwords |
| **164.308(a)(6)(i)** - Security Incident Procedures | A.5.24, A.5.25, A.5.26 | Required | Identify and respond to suspected or known security incidents |
| **164.308(a)(6)(ii)** - Response and Reporting | A.5.26, A.5.27 | Required | Mitigate harmful effects and document incidents and outcomes |
| **164.308(a)(7)(i)** - Contingency Plan | A.5.29, A.5.30 | Required | Establish and implement procedures for responding to emergencies |
| **164.308(a)(7)(ii)(A)** - Data Backup Plan | A.8.13 | Required | Establish procedures to create and maintain retrievable copies of ePHI |
| **164.308(a)(7)(ii)(B)** - Disaster Recovery Plan | A.5.30 | Required | Establish procedures to restore lost data |
| **164.308(a)(7)(ii)(C)** - Emergency Mode Operation Plan | A.5.30 | Required | Establish procedures to enable continuation of critical business processes |
| **164.308(a)(7)(ii)(D)** - Testing and Revision Procedures | A.5.30 | Addressable | Implement procedures for periodic testing and revision of contingency plans |
| **164.308(a)(7)(ii)(E)** - Applications and Data Criticality Analysis | A.5.30 | Addressable | Assess relative criticality of applications and data |
| **164.308(a)(8)** - Evaluation | A.5.8, A.5.37 | Required | Perform periodic technical and non-technical evaluation |

### Physical Safeguards (§164.310)

| HIPAA Requirement | ISO 27001:2022 Controls | Implementation | Description |
|-------------------|------------------------|----------------|-------------|
| **164.310(a)(1)** - Facility Access Controls | A.7.1, A.7.2, A.7.3 | Required | Limit physical access to electronic systems and facilities containing ePHI |
| **164.310(a)(2)(i)** - Contingency Operations | A.7.13, A.5.30 | Addressable | Establish procedures for facility access in support of restoration |
| **164.310(a)(2)(ii)** - Facility Security Plan | A.7.1, A.7.2 | Addressable | Implement policies to safeguard facility and equipment from unauthorized access |
| **164.310(a)(2)(iii)** - Access Control and Validation Procedures | A.7.2, A.7.3 | Addressable | Implement procedures to control and validate access to facilities |
| **164.310(a)(2)(iv)** - Maintenance Records | A.7.7 | Addressable | Implement policies to document repairs and modifications to physical components |
| **164.310(b)** - Workstation Use | A.7.8, A.7.10 | Required | Implement policies for workstation functions, manner of performance, and physical attributes |
| **164.310(c)** - Workstation Security | A.7.8, A.7.10 | Required | Implement physical safeguards for all workstations accessing ePHI |
| **164.310(d)(1)** - Device and Media Controls | A.7.10, A.8.10, A.8.11 | Required | Implement policies for receipt, removal, disposal, and reuse of hardware and media |
| **164.310(d)(2)(i)** - Disposal | A.8.10, A.8.11 | Required | Implement policies for final disposition of ePHI and hardware/media |
| **164.310(d)(2)(ii)** - Media Re-use | A.8.10, A.8.11 | Required | Implement procedures for removal of ePHI before media is reused |
| **164.310(d)(2)(iii)** - Accountability | A.5.9, A.7.10 | Addressable | Maintain record of movements of hardware and media containing ePHI |
| **164.310(d)(2)(iv)** - Data Backup and Storage | A.8.13 | Addressable | Create retrievable, exact copy of ePHI before equipment movement |

### Technical Safeguards (§164.312)

| HIPAA Requirement | ISO 27001:2022 Controls | Implementation | Description |
|-------------------|------------------------|----------------|-------------|
| **164.312(a)(1)** - Access Control | A.8.2, A.8.3, A.8.4, A.8.5 | Required | Implement technical policies to allow only authorized access to ePHI |
| **164.312(a)(2)(i)** - Unique User Identification | A.8.5 | Required | Assign unique identifier for tracking user identity |
| **164.312(a)(2)(ii)** - Emergency Access Procedure | A.8.2 | Required | Establish procedures for obtaining ePHI during emergency |
| **164.312(a)(2)(iii)** - Automatic Logoff | A.8.5 | Addressable | Implement electronic procedure that terminates session after predetermined inactivity |
| **164.312(a)(2)(iv)** - Encryption and Decryption | A.8.24 | Addressable | Implement mechanism to encrypt and decrypt ePHI |
| **164.312(b)** - Audit Controls | A.8.15, A.8.16 | Required | Implement hardware, software, and/or procedural mechanisms to record and examine activity |
| **164.312(c)(1)** - Integrity | A.8.16 | Required | Implement policies to protect ePHI from improper alteration or destruction |
| **164.312(c)(2)** - Mechanism to Authenticate ePHI | A.8.16 | Addressable | Implement electronic mechanisms to corroborate ePHI has not been altered |
| **164.312(d)** - Person or Entity Authentication | A.8.5 | Required | Implement procedures to verify person or entity seeking access is the one claimed |
| **164.312(e)(1)** - Transmission Security | A.8.23, A.8.24 | Required | Implement technical security measures to guard against unauthorized access to ePHI during transmission |
| **164.312(e)(2)(i)** - Integrity Controls | A.8.16, A.8.24 | Addressable | Implement security measures to ensure ePHI is not improperly modified during transmission |
| **164.312(e)(2)(ii)** - Encryption | A.8.24 | Addressable | Implement mechanism to encrypt ePHI whenever deemed appropriate |

### Key Considerations

1. **ISO 27001 alone is NOT sufficient for HIPAA compliance** - additional privacy controls required
2. **ISO 27799** (Health informatics - Information security management in health using ISO/IEC 27002) provides sector-specific guidance
3. **Addressable vs. Required:** HIPAA allows flexibility for addressable specifications based on risk assessment
4. **Business Associate Agreements (BAA):** HIPAA has specific requirements not covered by ISO 27001

---

## 4. SOC 2 TSC to ISO 27001:2022

**Source:** AICPA official mapping, compliance platform resources

### Framework Overview

**SOC 2 Trust Services Criteria (TSC)**
- Based on 2017 Trust Services Criteria (with March 2020 updates)
- 5 Trust Service Categories: Security, Availability, Processing Integrity, Confidentiality, Privacy
- 9 Common Criteria (CC1-CC9) under Security category
- **80% overlap** with ISO 27001 according to AICPA mapping

**Security Category (Mandatory for all SOC 2 reports)**

### Common Criteria (CC1-CC9) Mappings

| SOC 2 Common Criteria | ISO 27001:2022 Controls | Description |
|-----------------------|------------------------|-------------|
| **CC1: Control Environment** | A.5.1, A.5.2, A.5.3, A.5.4, A.6.2, A.6.8 | COSO Principle 1-5: Organization demonstrates commitment to integrity and ethical values; exercises oversight; establishes structure, authority, and responsibility; demonstrates commitment to competence; holds individuals accountable |
| **CC2: Communication and Information** | A.5.2, A.5.3, A.5.4, A.6.3 | COSO Principle 13-15: Obtains or generates quality information; communicates internally; communicates externally |
| **CC3: Risk Assessment** | A.5.7, A.5.8, A.5.9 | COSO Principle 6-9: Specifies suitable objectives; identifies and analyzes risk; assesses fraud risk; identifies and analyzes significant change |
| **CC4: Monitoring Activities** | A.5.8, A.5.37, A.8.15, A.8.16 | COSO Principle 16-17: Selects, develops, and performs ongoing evaluations; evaluates and communicates deficiencies |
| **CC5: Control Activities** | A.5.1, A.5.10, A.5.13, A.8.1 | COSO Principle 10-12: Selects and develops control activities; selects and develops general controls over technology; deploys through policies and procedures |
| **CC6: Logical and Physical Access Controls** | A.5.15, A.5.16, A.5.17, A.5.18, A.7.1, A.7.2, A.7.3, A.7.4, A.8.2, A.8.3, A.8.4, A.8.5 | Restricts logical and physical access through authentication, authorization, physical security |
| **CC7: System Operations** | A.5.24, A.5.25, A.5.26, A.5.27, A.5.28, A.8.6, A.8.7, A.8.8, A.8.14, A.8.15, A.8.16 | Detects and mitigates processing deviations, security events, and anomalies |
| **CC8: Change Management** | A.5.35, A.8.9, A.8.19, A.8.25, A.8.27, A.8.32 | Identifies need for changes; authorizes, designs, develops, configures, documents, tests, approves, and implements changes |
| **CC9: Risk Mitigation** | A.5.7, A.5.19, A.5.20, A.5.21, A.5.22, A.5.23, A.8.7, A.8.8 | Identifies, selects, develops risk mitigation activities; assesses third-party and vendor risk |

### Detailed Control Mappings by Category

#### CC6: Logical and Physical Access Controls (Detailed)

| SOC 2 Control | ISO 27001:2022 | Description |
|---------------|----------------|-------------|
| CC6.1 - Logical and physical access controls | A.5.15, A.7.1, A.7.2, A.8.2, A.8.3 | Strict logical and physical access controls; role-based permissions; network segmentation; facility entry management |
| CC6.2 - New internal users | A.5.16, A.5.18, A.8.2 | Registration and authorization of new users |
| CC6.3 - New external parties | A.5.19, A.5.20, A.5.21 | Authorization before external party access |
| CC6.4 - User identity credentials | A.8.5 | Issuance, management, and removal of user credentials |
| CC6.5 - Authentication methods | A.8.5 | Multi-factor authentication; strong authentication |
| CC6.6 - Encryption of data | A.8.11, A.8.24 | Data encrypted in transit and at rest; S3 bucket policies; RDS, EBS, DynamoDB encryption; AWS KMS |
| CC6.7 - Access rights removal | A.5.18, A.6.4, A.8.2 | Timely removal of access when no longer required |
| CC6.8 - Privileged access | A.8.2, A.8.18 | Restricted and monitored privileged access |

#### CC7: System Operations (Detailed)

| SOC 2 Control | ISO 27001:2022 | Description |
|---------------|----------------|-------------|
| CC7.1 - Anomaly detection | A.8.16 | Monitors system components for anomalies indicative of malicious acts, natural disasters, errors |
| CC7.2 - System monitoring | A.8.15, A.8.16 | Monitors system components and operations for anomalies; analyzes security events |
| CC7.3 - Incident response | A.5.24, A.5.25, A.5.26 | Identifies, reports, and acts upon system security breaches |
| CC7.4 - Response and mitigation | A.5.26, A.5.27 | Mitigates ongoing events; learns from incidents |
| CC7.5 - Detection of malicious software | A.8.7 | Implements detection mechanisms to identify and protect against malware |

#### CC8: Change Management (Detailed)

| SOC 2 Control | ISO 27001:2022 | Description |
|---------------|----------------|-------------|
| CC8.1 - Change management process | A.8.32 | Authorizes, designs, develops, tests, approves, implements changes |
| CC8.2 - Infrastructure and software | A.5.35, A.8.9 | Change management for infrastructure and software |
| CC8.3 - Emergency changes | A.8.14, A.8.32 | Procedures for emergency changes |

### Additional Trust Service Categories

| SOC 2 Category | ISO 27001:2022 Controls | Description |
|----------------|------------------------|-------------|
| **Availability (A)** | A.5.29, A.5.30, A.8.6, A.8.13, A.8.14 | System available for operation and use as committed; includes backup, redundancy, capacity |
| **Processing Integrity (PI)** | A.8.16, A.8.25, A.8.27, A.8.29 | System processing is complete, valid, accurate, timely, and authorized |
| **Confidentiality (C)** | A.8.11, A.8.24, A.5.12, A.5.34 | Information designated as confidential is protected as committed; encryption, access controls, NDAs |
| **Privacy (P)** | A.5.34, A.7.4, A.8.10, A.8.11 | Personal information collected, used, retained, disclosed, disposed in conformity with commitments |

### Key Considerations

1. **80% Overlap:** AICPA mapping shows approximately 80% overlap between ISO 27001 and SOC 2
2. **SOC 2 is Less Prescriptive:** Requires custom mapping and interpretation based on organization's commitments
3. **Evidence Chain:** Both frameworks can share common evidence for audit purposes
4. **AICPA Official Mapping:** Available as "Mapping: 2017 Trust Services Criteria to ISO 27001" Excel spreadsheet
5. **Dual Compliance:** Organizations can leverage ISO 27001 ISMS to streamline SOC 2 audits

---

## 5. GDPR to ISO 27001:2022

**Source:** NQA, IT Governance, GDPR-ISO mapping whitepapers

### Framework Overview

**GDPR (General Data Protection Regulation)**
- EU Regulation (EU) 2016/679
- Effective May 25, 2018
- 99 Articles across 11 Chapters
- Focuses on data privacy and protection of EU citizens
- Extraterritorial scope

**Important:** ISO 27001 certification alone is NOT sufficient for GDPR compliance. GDPR extends beyond security to data privacy rights (consent, portability, right to be forgotten). **ISO 27701** (Privacy Information Management System) provides the privacy extension to ISO 27001.

### Key GDPR Articles Mapped to ISO 27001:2022

#### Chapter II: Principles (Articles 5-11)

| GDPR Article | ISO 27001:2022 Controls | Description |
|--------------|------------------------|-------------|
| **Article 5 - Principles relating to processing of personal data** | A.5.34, A.8.11, A.8.10 | Lawfulness, fairness, transparency; purpose limitation; data minimization; accuracy; storage limitation; integrity and confidentiality; accountability |
| **Article 6 - Lawfulness of processing** | A.5.34 | Legal basis for processing (consent, contract, legal obligation, vital interests, public task, legitimate interests) |

#### Chapter III: Rights of the Data Subject (Articles 12-23)

| GDPR Article | ISO 27001:2022 Controls | Description |
|--------------|------------------------|-------------|
| **Article 12 - Transparent information** | A.5.34 | Transparent, concise, intelligible communication with data subjects |
| **Article 15 - Right of access** | A.5.34, A.8.11 | Data subject's right to obtain confirmation whether personal data is being processed |
| **Article 16 - Right to rectification** | A.5.34 | Right to obtain rectification of inaccurate personal data |
| **Article 17 - Right to erasure ('right to be forgotten')** | A.5.34, A.8.10 | Right to obtain erasure of personal data |
| **Article 18 - Right to restriction of processing** | A.5.34 | Right to restrict processing in certain circumstances |
| **Article 20 - Right to data portability** | A.5.34 | Right to receive personal data in structured, commonly used, machine-readable format |

#### Chapter IV: Controller and Processor (Articles 24-43)

| GDPR Article | ISO 27001:2022 Controls | Description |
|--------------|------------------------|-------------|
| **Article 24 - Responsibility of the controller** | A.5.1, A.5.8 | Implement appropriate technical and organizational measures to ensure GDPR compliance |
| **Article 25 - Data protection by design and by default** | A.5.1, A.8.25, A.8.27, A.8.28 | Implement technical and organizational measures during design stage; privacy by design and default |
| **Article 28 - Processor** | A.5.19, A.5.20, A.5.21, A.5.22 | Processing by processor shall be governed by contract; processor obligations |
| **Article 30 - Records of processing activities** | A.5.9, A.5.34, A.8.11 | Controllers and processors must maintain records of processing activities; asset inventory; data mapping |
| **Article 32 - Security of processing** | A.5.1, A.8.1, A.8.2, A.8.5, A.8.7, A.8.11, A.8.13, A.8.15, A.8.16, A.8.20, A.8.24 | Appropriate technical and organizational security measures: pseudonymization and encryption; confidentiality, integrity, availability, resilience; restoration capability; testing and evaluation |
| **Article 33 - Notification of personal data breach** | A.5.24, A.5.25, A.5.26 | Notification to supervisory authority within 72 hours of discovery |
| **Article 34 - Communication of personal data breach** | A.5.26 | Communication to data subject when breach likely to result in high risk |
| **Article 35 - Data protection impact assessment (DPIA)** | A.5.8 | DPIA required when processing likely to result in high risk; risk assessment |
| **Article 37 - Designation of the data protection officer (DPO)** | A.5.3, A.5.4 | Appointment of DPO in certain circumstances; roles and responsibilities |

#### Chapter V: Transfers of Personal Data to Third Countries (Articles 44-50)

| GDPR Article | ISO 27001:2022 Controls | Description |
|--------------|------------------------|-------------|
| **Article 44 - General principle for transfers** | A.5.19, A.5.34 | Transfer to third countries only if conditions complied with |
| **Article 46 - Transfers subject to appropriate safeguards** | A.5.14, A.5.19, A.5.20 | Appropriate safeguards for international transfers (e.g., Standard Contractual Clauses) |

#### Chapter VI: Independent Supervisory Authorities (Articles 51-59)

| GDPR Article | ISO 27001:2022 Controls | Description |
|--------------|------------------------|-------------|
| **Article 58 - Powers of supervisory authorities** | - | Investigative, corrective, authorization, and advisory powers (no direct ISO mapping) |

### Detailed Article 32 (Security of Processing) Mapping

**Article 32 Requirements → ISO 27001:2022**

| Article 32 Requirement | ISO 27001:2022 Controls | Description |
|------------------------|------------------------|-------------|
| 32(1)(a) - Pseudonymization and encryption | A.8.11, A.8.24 | Pseudonymization and encryption of personal data |
| 32(1)(b) - Confidentiality, integrity, availability, resilience | A.8.1, A.8.7, A.8.13, A.8.15, A.8.16, A.8.20, A.8.24 | Ensure ongoing confidentiality, integrity, availability and resilience of processing systems and services |
| 32(1)(c) - Restoration capability | A.5.29, A.5.30, A.8.13, A.8.14 | Ability to restore availability and access to personal data in timely manner after physical or technical incident |
| 32(1)(d) - Testing and evaluation | A.5.37, A.8.8 | Process for regularly testing, assessing, evaluating effectiveness of technical and organizational measures |

### ISO 27701 Extension for GDPR Privacy Requirements

**ISO 27701:2019** - Privacy Information Management System (PIMS)
- Extension to ISO 27001 and ISO 27002
- Specifically designed to help with GDPR compliance
- Provides additional privacy controls beyond security

| GDPR Privacy Requirement | ISO 27701 Guidance | ISO 27001:2022 Base |
|--------------------------|-------------------|---------------------|
| Consent management | ISO 27701 Control 7.2.1 | A.5.34 |
| Data subject rights (access, erasure, portability) | ISO 27701 Control 7.3.2, 7.3.4, 7.3.5 | A.5.34, A.8.10, A.8.11 |
| Privacy by design | ISO 27701 Control 7.2.8 | A.8.25, A.8.27 |
| Data protection impact assessment | ISO 27701 Control 7.2.7 | A.5.8 |
| Records of processing | ISO 27701 Control 7.4.8 | A.5.9, A.5.34 |

### Key Considerations

1. **ISO 27001 + ISO 27701 for Full GDPR Alignment:** While ISO 27001 provides the security framework, ISO 27701 adds the privacy controls necessary for GDPR
2. **Article 32 Strong Alignment:** Article 32 (Security of Processing) maps well to ISO 27001:2022 Annex A controls
3. **Privacy Rights Gap:** ISO 27001 alone doesn't address data subject rights (Articles 15-22); requires ISO 27701 or separate privacy program
4. **Documentation Requirements:** Both frameworks emphasize documentation, policies, and procedures
5. **Risk-Based Approach:** Both GDPR (Articles 24, 25, 32) and ISO 27001 require risk-based approach
6. **Breach Notification:** GDPR's 72-hour breach notification (Article 33) requires robust incident management (A.5.24-5.28)

### GDPR-Specific Requirements NOT in ISO 27001

- Consent mechanisms and management
- Right to data portability (Article 20)
- Right to be forgotten / erasure (Article 17)
- Data Protection Officer (DPO) appointment criteria
- Data Protection Impact Assessments (DPIA) specific methodology
- Cross-border data transfer mechanisms (Standard Contractual Clauses, Binding Corporate Rules)
- Supervisory authority interaction and cooperation

---

## Key Findings and Recommendations

### Cross-Framework Insights

1. **Common Ground - Access Control:**
   All frameworks emphasize strong access control mechanisms:
   - NIST 800-53: AC family controls
   - PCI DSS: Requirements 7 & 8
   - HIPAA: 164.308(a)(4), 164.312(a)
   - SOC 2: CC6
   - GDPR: Article 32
   - ISO 27001:2022: A.5.15-5.18, A.8.2-8.5

2. **Common Ground - Logging and Monitoring:**
   All frameworks require comprehensive logging and monitoring:
   - NIST 800-53: AU and SI families
   - PCI DSS: Requirement 10
   - HIPAA: 164.308(a)(1)(ii)(D), 164.312(b)
   - SOC 2: CC7
   - GDPR: Article 32(1)(d)
   - ISO 27001:2022: A.8.15-8.16

3. **Common Ground - Incident Management:**
   Incident response is universal:
   - NIST 800-53: IR family
   - PCI DSS: Requirement 12.10
   - HIPAA: 164.308(a)(6)
   - SOC 2: CC7.3-7.4
   - GDPR: Articles 33-34
   - ISO 27001:2022: A.5.24-5.28

4. **Common Ground - Risk Management:**
   Risk-based approach across frameworks:
   - NIST 800-53: RA family
   - PCI DSS: Requirement 12
   - HIPAA: 164.308(a)(1)
   - SOC 2: CC3
   - GDPR: Articles 24, 25, 32, 35
   - ISO 27001:2022: A.5.8

### Coverage Analysis

| Framework | Direct Mapping % | Gap Areas | Complementary Standards |
|-----------|-----------------|-----------|------------------------|
| **NIST 800-53 Rev 5** | ~70-80% | Detailed technical specifications | Use together for federal compliance |
| **PCI DSS v4.0** | ~26% | Cardholder data-specific requirements | Both needed for payment security |
| **HIPAA Security Rule** | ~50% | Privacy safeguards, BAA requirements | Add ISO 27799 for healthcare |
| **SOC 2 TSC** | ~80% | Customer-specific commitments | Highly compatible, shared evidence |
| **GDPR** | ~60% (security only) | Privacy rights, consent, DPO, transfers | Add ISO 27701 for privacy |

### Implementation Recommendations

1. **Start with ISO 27001:2022 as Foundation:**
   - Provides comprehensive ISMS framework
   - 93 controls cover broad security landscape
   - Risk-based approach allows tailoring
   - Recognized globally

2. **Layer Additional Frameworks Based on Requirements:**
   - **Federal/Government:** Add NIST 800-53 Rev 5
   - **Payment Card Industry:** Add PCI DSS v4.0
   - **Healthcare (US):** Add HIPAA + ISO 27799
   - **SaaS/Cloud Services:** Add SOC 2
   - **EU Data Protection:** Add ISO 27701 + GDPR-specific privacy controls

3. **Leverage Control Mapping for Efficiency:**
   - Use mappings to avoid duplicate work
   - Build unified evidence repository
   - Implement controls once, demonstrate compliance multiple ways
   - Use GRC platforms to manage cross-framework compliance

4. **Focus on High-Overlap Areas First:**
   - Access control (identity and authentication)
   - Logging and monitoring
   - Incident response
   - Risk management
   - Security awareness training
   - Change management
   - Vulnerability management

5. **Address Framework-Specific Gaps:**
   - **NIST:** Detailed technical specifications and federal requirements
   - **PCI DSS:** Cardholder data-specific controls, QSA validation
   - **HIPAA:** Privacy safeguards, Business Associate Agreements
   - **SOC 2:** Customer-specific controls, Type II continuous monitoring
   - **GDPR:** Data subject rights, consent management, cross-border transfers

### Using This Mapping Document

1. **Identify Your Compliance Requirements:**
   Determine which frameworks apply to your organization based on industry, geography, and customer requirements.

2. **Build Control Matrix:**
   Create a matrix showing which ISO 27001 controls satisfy requirements across multiple frameworks.

3. **Gap Analysis:**
   Identify controls required by other frameworks not covered by ISO 27001.

4. **Implementation Prioritization:**
   - Implement controls that satisfy multiple frameworks first
   - Address framework-specific requirements second
   - Use risk assessment to prioritize within each category

5. **Evidence Management:**
   - Maintain centralized evidence repository
   - Tag evidence to multiple framework requirements
   - Streamline audit processes across frameworks

6. **Continuous Improvement:**
   - Update mappings as frameworks evolve
   - Monitor for new framework versions
   - Maintain awareness of emerging requirements

---

## Authoritative Sources

### Official Mapping Documents

1. **NIST SP 800-53 Rev 5 to ISO/IEC 27001:2022**
   - Source: NIST Computer Security Resource Center (CSRC)
   - Location: https://csrc.nist.gov/projects/olir/informative-reference-catalog/details?referenceId=155
   - Document: Available through NIST OLIR Program
   - Status: Official NIST crosswalk

2. **SOC 2 TSC to ISO 27001**
   - Source: AICPA & CIMA
   - Document: "Mapping: 2017 Trust Services Criteria to ISO 27001"
   - Location: https://www.aicpa-cima.com/resources/download/mapping-2017-trust-services-criteria-to-iso-27001
   - Format: Excel spreadsheet
   - Status: Official AICPA mapping

3. **GDPR to ISO 27001**
   - Source: NQA, BSI Group, IT Governance
   - Documents: "GDPR V ISO 27001 Mapping Table" (NQA)
   - Note: Multiple industry sources; no single official mapping from EU or ISO

4. **HIPAA to ISO 27001**
   - Source: BSI Group, Pivot Point Security, healthcare compliance consultancies
   - Documents: "HIPAA and ISO/IEC 27001: Implement Once, Comply Many" (BSI)
   - Note: Industry-created mappings; HHS does not provide official ISO mapping

5. **PCI DSS to ISO 27001**
   - Source: ISMS.online, IJSR, compliance platforms
   - Documents: "Comparative Study between PCI-DSS v4.0 and ISO/IEC 27001:2022"
   - Note: Industry-created mappings; PCI SSC does not provide official ISO mapping

### Framework Documentation

1. **ISO/IEC 27001:2022** - Information Security Management Systems - Requirements
2. **ISO/IEC 27002:2022** - Information Security Controls (implementation guidance)
3. **ISO/IEC 27701:2019** - Privacy Information Management System
4. **NIST SP 800-53 Revision 5** - Security and Privacy Controls for Information Systems and Organizations
5. **PCI DSS v4.0** - Payment Card Industry Data Security Standard
6. **HIPAA Security Rule** - 45 CFR Part 164, Subparts A and C
7. **AICPA TSC 2017** - Trust Services Criteria (with March 2020 updates)
8. **GDPR** - Regulation (EU) 2016/679

### Research and Analysis

1. International Journal of Scientific Research (IJSR) - "Comparative Study between PCI-DSS v4.0 and ISO/IEC 27001:2022"
2. ISACA Journal - "Comparison of PCI DSS and ISO/IEC 27001 Standards"
3. NIST IR 8477 - "Cybersecurity Framework Profile for Public Comment - CSF 2.0 Informative References"
4. Security Checkbox - "Framework Mapping Database"
5. Secure Controls Framework (SCF) - "Set Theory Relationship Mapping (STRM)"

### Additional Resources

1. **NIST OLIR Program:** https://csrc.nist.gov/projects/olir
2. **AICPA Trust Services:** https://www.aicpa-cima.com/resources/landing/trust-services-criteria
3. **ISO 27001 Official:** https://www.iso.org/standard/27001
4. **PCI Security Standards Council:** https://www.pcisecuritystandards.org
5. **HHS HIPAA Information:** https://www.hhs.gov/hipaa/
6. **GDPR Official Text:** https://gdpr-info.eu/

---

## Document Version Control

| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0 | 2025-11-13 | Research Compilation | Initial comprehensive mapping document |

---

## Disclaimer

This mapping document is provided for informational purposes to assist organizations in understanding relationships between cybersecurity and compliance frameworks. While based on authoritative sources and official mappings where available, this document:

1. Should not be considered legal or compliance advice
2. May not reflect the most current version of all frameworks
3. Represents general mappings that may require customization for specific organizational contexts
4. Should be validated with qualified compliance professionals, auditors, or legal counsel
5. Does not guarantee compliance with any framework
6. Should be supplemented with official framework documentation

Organizations should:
- Consult official framework documentation
- Engage qualified assessors and auditors
- Conduct thorough gap analyses
- Implement controls based on specific risk assessments
- Maintain awareness of framework updates and changes

**Last Updated:** November 13, 2025
**Next Review:** Quarterly or upon significant framework updates

---

*End of Document*
