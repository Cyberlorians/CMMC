# Domain Controller Security Event Logging

### CMMC Level 2 (NIST SP 800-171 R2) + Microsoft Defender for Identity (MDI) Event Mapping

![Scope](https://img.shields.io/badge/Scope-Domain_Controllers-1f6feb?style=for-the-badge)
![CMMC](https://img.shields.io/badge/CMMC-Level_2-2ea043?style=for-the-badge)
![Framework](https://img.shields.io/badge/NIST-800--171_R2-8957e5?style=for-the-badge)
![MDI](https://img.shields.io/badge/Defender_for_Identity-Required_Events-d29922?style=for-the-badge)

> **Purpose:** A single, auditor-ready reference that maps every Domain Controller (DC) security Event ID to (1) its **CMMC Level 2 / NIST SP 800-171 R2** control, (2) whether it is a **Microsoft Defender for Identity (MDI)** required event, and (3) the exact **Group Policy path / audit subcategory** that generates it.
>
> **Applies to:** Domain Controllers only. Member Server object-access events (file/registry/handle) are intentionally excluded.

---

## How to read this document

| Label | Meaning |
| :--- | :--- |
| **CMMC Requirement** | Event supports a CMMC **Level 2** control (NIST SP 800-171 R2). The specific control family and number are named in full. |
| **MDI Requirement** | Event is on Microsoft's authoritative "Required Windows events" list for the Defender for Identity DC sensor. |
| **GPO Path / Subcategory** | The Advanced Audit Policy subcategory (or Security Option) that must be enabled to generate the event. |

### CMMC control families referenced

| Code | Full Family Name |
| :--- | :--- |
| **AC** | Access Control |
| **AU** | Audit and Accountability |
| **CM** | Configuration Management |
| **IA** | Identification and Authentication |

### Where each label comes from

- **CMMC Level 2** — Every Audit and Accountability control (**3.3.1 – 3.3.9**) is a **Level 2** requirement under NIST SP 800-171 R2. Level 1 (FCI, FAR 52.204-21) requires **no** audit logging; Level 3 (NIST SP 800-172) reuses these same logs for threat-hunting/SOC objectives and adds **no new Event IDs**.
- **MDI Requirement** — Microsoft Learn, *Configure Windows event auditing → Required Windows events* (Defender for Identity DC sensor).

---

## CMMC Level context

| Level | Basis | Audit Logging Required? |
| :--- | :--- | :--- |
| **Level 1 — Basic Safeguarding of FCI** | 15 requirements (FAR clause 52.204-21) | No — Audit & Accountability family not in scope |
| **Level 2 — Broad Protection of CUI** | 110 requirements (**NIST SP 800-171 R2**) | **Yes — the entire AU family lives here** |
| **Level 3 — Protection Against APTs** | Level 2 + 24 requirements (NIST SP 800-172) | Consumes these logs for hunting/SOC; no new Event IDs |

> **Call-out:** *All Domain Controller security-event logging in this document satisfies CMMC **Level 2** (NIST SP 800-171 R2, Audit and Accountability family).*

---

## GPO base path

All **Advanced Audit Policy** subcategories below are located under:

```
Computer Configuration
  └─ Policies
     └─ Windows Settings
        └─ Security Settings
           └─ Advanced Audit Policy Configuration
              └─ Audit Policies
                 └─ <Category> ▸ <Subcategory>
```

The **GPO Path / Subcategory** column shows the `<Category> ▸ <Subcategory>` portion. Non-Advanced-Audit-Policy items (NTLM, log clearing) show their full path explicitly.

> **Recommended state:** configure **Success and Failure** for all subcategories below unless a subcategory does not support Failure auditing.

---

## Account Logon — Kerberos & NTLM

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4768** | Kerberos authentication ticket (TGT) requested | AU 3.3.1 (Audit and Accountability); IA 3.5.2 | — | Account Logon ▸ Audit Kerberos Authentication Service |
| **4771** | Kerberos pre-authentication failed | IA 3.5.2 (Identification and Authentication); AC 3.1.8 | — | Account Logon ▸ Audit Kerberos Authentication Service |
| **4776** | Domain Controller validated credentials (NTLM) | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Logon ▸ Audit Credential Validation |
| **8004** | NTLM authentication | AU 3.3.1 (Audit and Accountability) | ✅ Required | Local Policies ▸ Security Options ▸ *Network security: Restrict NTLM: Audit NTLM authentication in this domain* |
| **5168** | SPN check for SMB/SMB2 failed | AU 3.3.1 (Audit and Accountability) | — | Local Policies ▸ Security Options ▸ *Network security: Restrict NTLM: Audit NTLM authentication in this domain* |

---

## Logon / Logoff

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4624** | An account was successfully logged on | AU 3.3.2 (Audit and Accountability — traceability to individuals) | — | Logon/Logoff ▸ Audit Logon |
| **4625** | An account failed to log on | AC 3.1.8 (Access Control — limit unsuccessful logon attempts) | — | Logon/Logoff ▸ Audit Logon |
| **4634** | An account was logged off | AU 3.3.1 (Audit and Accountability) | — | Logon/Logoff ▸ Audit Logoff |
| **4647** | User-initiated logoff | AU 3.3.1 (Audit and Accountability) | — | Logon/Logoff ▸ Audit Logoff |
| **4672** | Special privileges assigned to new logon | AC 3.1.7 (Access Control — capture execution of privileged functions) | — | Logon/Logoff ▸ Audit Special Logon |

---

## Account Management — User Accounts

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4720** | User account created | AU 3.3.1 (Audit and Accountability) | — | Account Management ▸ Audit User Account Management |
| **4722** | User account enabled | AU 3.3.1 (Audit and Accountability) | — | Account Management ▸ Audit User Account Management |
| **4723** | Password change attempted | IA 3.5.x (Identification and Authentication) | — | Account Management ▸ Audit User Account Management |
| **4724** | Password reset attempted | IA 3.5.x (Identification and Authentication) | — | Account Management ▸ Audit User Account Management |
| **4725** | User account disabled | AU 3.3.1 (Audit and Accountability) | — | Account Management ▸ Audit User Account Management |
| **4726** | User account deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit User Account Management |
| **4738** | User account changed | AU 3.3.1 (Audit and Accountability) | — | Account Management ▸ Audit User Account Management |
| **4740** | User account locked out | AC 3.1.8 (Access Control — limit unsuccessful logon attempts) | — | Account Management ▸ Audit User Account Management |

---

## Account Management — Security & Distribution Groups

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4728** | Member added to global security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4729** | Member removed from global security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4730** | Global security group deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4732** | Member added to local security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4733** | Member removed from local security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4756** | Member added to universal security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4757** | Member removed from universal security group | AC 3.1.5 (Access Control — least privilege) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4758** | Universal security group deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Security Group Management |
| **4753** | Global distribution group deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Distribution Group Management |
| **4763** | Universal distribution group deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Distribution Group Management |

---

## Account Management — Computer Accounts

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4741** | Computer account created | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Computer Account Management |
| **4743** | Computer account deleted | AU 3.3.1 (Audit and Accountability) | ✅ Required | Account Management ▸ Audit Computer Account Management |

---

## Directory Service (DS) Access

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4662** | Operation performed on a directory object (**DCSync**) | AU 3.3.1 (Audit and Accountability) | ✅ Required | DS Access ▸ Audit Directory Service Access *(also requires SACL on the domain object)* |
| **5136** | Directory service object modified | AU 3.3.1 (Audit and Accountability); CM 3.4.3 | ✅ Required | DS Access ▸ Audit Directory Service Changes |
| **5137** | Directory service object created | AU 3.3.1 (Audit and Accountability) | — | DS Access ▸ Audit Directory Service Changes |
| **5141** | Directory service object deleted | AU 3.3.1 (Audit and Accountability) | — | DS Access ▸ Audit Directory Service Changes |

> **Critical:** *Audit Directory Service Changes* defaults to **No Auditing** on a fresh install. Events **5136 / 5137 / 5141** will never generate until this subcategory is explicitly enabled.

---

## Privilege Use

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4673** | A privileged service was called | AC 3.1.7 (Access Control — capture privileged function execution) | — | Privilege Use ▸ Audit Sensitive Privilege Use |
| **4674** | An operation was attempted on a privileged object | AC 3.1.7 (Access Control — capture privileged function execution) | — | Privilege Use ▸ Audit Sensitive Privilege Use |

---

## Policy Change

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4719** | System audit policy was changed | AU 3.3.8 (Audit and Accountability — protect audit information) | — | Policy Change ▸ Audit Audit Policy Change |
| **4713** | Kerberos policy was changed | CM 3.4.3 (Configuration Management — log changes) | — | Policy Change ▸ Audit Authentication Policy Change |
| **4716** | Trusted domain information was modified | CM 3.4.3 (Configuration Management — log changes) | — | Policy Change ▸ Audit Authentication Policy Change |
| **4739** | Domain policy was changed | CM 3.4.3 (Configuration Management — log changes) | — | Policy Change ▸ Audit Authentication Policy Change |

---

## System Integrity

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **1102** | The security audit log was cleared | AU 3.3.8 (Audit and Accountability — protect audit information) | — | *Always logged when the Security log is cleared (no subcategory required); commonly grouped under System ▸ Audit Other System Events* |
| **4616** | The system time was changed | AU 3.3.7 (Audit and Accountability — time stamps) | — | System ▸ Audit Security State Change |
| **7045** | A new service was installed | CM 3.4.3 (Configuration Management — log changes) | ✅ Required | System ▸ Audit Security System Extension |

---

## AD Certificate Services — *only if the DC is also a Certification Authority (CA)*

| Event | Description | CMMC Requirement (Level 2) | MDI Requirement | GPO Path / Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4870** | Certificate Services revoked a certificate | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services *(+ enable CA auditing)* |
| **4882** | Security permissions for Certificate Services changed | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |
| **4885** | Audit filter for Certificate Services changed | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |
| **4887** | Certificate Services approved a request and issued a certificate | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |
| **4888** | Certificate Services denied a certificate request | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |
| **4890** | Certificate manager settings for Certificate Services changed | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |
| **4896** | One or more rows deleted from the certificate database | AU 3.3.1 (Audit and Accountability) | ✅ Required (AD CS) | Object Access ▸ Audit Certification Services |

---

## Summary — coverage at a glance

| Source | Count | Event IDs |
| :--- | :---: | :--- |
| **CMMC Level 2 only** | 21 | 4768, 4771, 5168, 4624, 4625, 4634, 4647, 4672, 4720, 4722, 4723, 4724, 4725, 4738, 4740, 4673, 4674, 4719, 4713, 4716, 4739, 5137, 5141, 4616, 1102 |
| **MDI Requirement only** | 4 | 4730, 4753, 4758, 4763, 8004 |
| **Both CMMC L2 + MDI** | — | 4776, 4726, 4728, 4729, 4732, 4733, 4756, 4757, 4741, 4743, 4662, 5136, 7045 |
| **AD CS (CA role only)** | 7 | 4870, 4882, 4885, 4887, 4888, 4890, 4896 |

> **Efficiency note:** The 13 events in the "Both" row satisfy **CMMC Level 2 and MDI simultaneously** — one GPO + one Data Collection Rule covers both mandates.

---

## Audit policy configuration guardrails

1. **Force the subcategory override.** Enable *Computer Configuration ▸ Policies ▸ Windows Settings ▸ Security Settings ▸ Local Policies ▸ Security Options ▸ "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"*. Confirm the registry value `HKLM\System\CurrentControlSet\Control\LSA\SCENoApplyLegacyAuditPolicy = 1`.
2. **Set the 9 legacy categories to "Not Defined"** (not "No Auditing," which actively overrides the advanced subcategories).
3. **Enable DS Access ▸ Audit Directory Service Changes** — off by default; required for 5136/5137/5141.
4. **Verify with `auditpol.exe`, not `rsop.msc`** — the Resultant Set of Policy console does not display Advanced Audit Policy subcategories.
5. **Cover the PDC Emulator** — GPMC-initiated directory changes (5136/5137/5141) are written to the PDC Emulator by default.
6. **Use a dedicated GPO linked to the Domain Controllers OU** — do not modify the Default Domain Controllers Policy or link at the domain root.

---

## Authoritative sources

- **Microsoft Learn** — [Configure Windows event auditing (Defender for Identity)](https://learn.microsoft.com/defender-for-identity/deploy/configure-windows-event-collection)
- **Microsoft Learn** — [Advanced Audit Policy Configuration (AD DS)](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- **Microsoft Learn** — [Windows security baseline — System Audit Policies](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows)
- **DoD CIO** — [About CMMC](https://dodcio.defense.gov/cmmc/About/)
- **NIST SP 800-171 R2** — Audit and Accountability (3.3.1 – 3.3.9), Access Control, Configuration Management, Identification and Authentication families
- **CMMC 2.0 KQL Alignment** — [Cyberlorians NIST Framework Dashboard](https://cyberlorians.github.io/nistframework/)
