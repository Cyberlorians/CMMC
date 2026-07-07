# Domain Controller Security Event Logging

### CMMC Level 2 (NIST SP 800-171 R2) + Microsoft Defender for Identity (MDI)

![Scope](https://img.shields.io/badge/Scope-Domain_Controllers-1f6feb?style=for-the-badge)
![CMMC](https://img.shields.io/badge/CMMC-Level_2-2ea043?style=for-the-badge)
![Framework](https://img.shields.io/badge/NIST-800--171_R2-8957e5?style=for-the-badge)
![MDI](https://img.shields.io/badge/Defender_for_Identity-Sensor-d29922?style=for-the-badge)

> Maps every Domain Controller security **Event ID** to its **CMMC** control, its **MDI** requirement, and the **Group Policy subcategory** that generates it.
> **Applies to Domain Controllers only.**

---

## Legend

| Column | Meaning |
| :--- | :--- |
| **CMMC** | ✅ + control number. Every DC event here is a **CMMC Level 2** requirement (NIST SP 800-171 R2). |
| **MDI** | ✅ = required by the Microsoft Defender for Identity DC sensor. Blank = not required by MDI. |
| **GPO Subcategory** | Advanced Audit Policy subcategory (or Security Option) that must be enabled. |

**CMMC control families:**

| Code | Full Family Name |
| :---: | :--- |
| **AC** | Access Control |
| **AU** | Audit and Accountability |
| **CM** | Configuration Management |
| **IA** | Identification and Authentication |

> Both columns use the same **✅** marker so they read consistently at a glance.

---

## GPO base path

All subcategories live under one path — only the last two segments change per event:

```
Computer Configuration ▸ Policies ▸ Windows Settings ▸ Security Settings
  ▸ Advanced Audit Policy Configuration ▸ Audit Policies ▸ <Category> ▸ <Subcategory>
```

Configure **Success and Failure** for every subcategory below.

---

## 1. Account Logon — Kerberos & NTLM

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4768** | Kerberos TGT requested | ✅ AU 3.3.1 | | Account Logon ▸ Kerberos Authentication Service |
| **4771** | Kerberos pre-authentication failed | ✅ IA 3.5.2 | | Account Logon ▸ Kerberos Authentication Service |
| **4776** | Credentials validated (NTLM) | ✅ AU 3.3.1 | ✅ | Account Logon ▸ Credential Validation |
| **8004** | NTLM authentication | ✅ AU 3.3.1 | ✅ | Security Options ▸ *Restrict NTLM: Audit NTLM authentication in this domain* |
| **5168** | SPN check for SMB/SMB2 failed | ✅ AU 3.3.1 | | Security Options ▸ *Restrict NTLM: Audit NTLM authentication in this domain* |

## 2. Logon / Logoff

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4624** | Account logged on | ✅ AU 3.3.2 | | Logon/Logoff ▸ Audit Logon |
| **4625** | Account failed to log on | ✅ AC 3.1.8 | | Logon/Logoff ▸ Audit Logon |
| **4634** | Account logged off | ✅ AU 3.3.1 | | Logon/Logoff ▸ Audit Logoff |
| **4647** | User-initiated logoff | ✅ AU 3.3.1 | | Logon/Logoff ▸ Audit Logoff |
| **4672** | Special privileges assigned to logon | ✅ AC 3.1.7 | | Logon/Logoff ▸ Special Logon |

## 3. Account Management — User Accounts

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4720** | User account created | ✅ AU 3.3.1 | | Account Management ▸ User Account Management |
| **4722** | User account enabled | ✅ AU 3.3.1 | | Account Management ▸ User Account Management |
| **4723** | Password change attempted | ✅ IA 3.5.2 | | Account Management ▸ User Account Management |
| **4724** | Password reset attempted | ✅ IA 3.5.2 | | Account Management ▸ User Account Management |
| **4725** | User account disabled | ✅ AU 3.3.1 | | Account Management ▸ User Account Management |
| **4726** | User account deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ User Account Management |
| **4738** | User account changed | ✅ AU 3.3.1 | | Account Management ▸ User Account Management |
| **4740** | User account locked out | ✅ AC 3.1.8 | | Account Management ▸ User Account Management |

## 4. Account Management — Security & Distribution Groups

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4728** | Member added to global security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4729** | Member removed from global security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4730** | Global security group deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ Security Group Management |
| **4732** | Member added to local security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4733** | Member removed from local security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4756** | Member added to universal security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4757** | Member removed from universal security group | ✅ AC 3.1.5 | ✅ | Account Management ▸ Security Group Management |
| **4758** | Universal security group deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ Security Group Management |
| **4753** | Global distribution group deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ Distribution Group Management |
| **4763** | Universal distribution group deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ Distribution Group Management |

## 5. Account Management — Computer Accounts

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4741** | Computer account created | ✅ AU 3.3.1 | ✅ | Account Management ▸ Computer Account Management |
| **4743** | Computer account deleted | ✅ AU 3.3.1 | ✅ | Account Management ▸ Computer Account Management |

## 6. Directory Service (DS) Access

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4662** | Operation on a directory object (**DCSync**) | ✅ AU 3.3.1 | ✅ | DS Access ▸ Directory Service Access |
| **5136** | Directory object modified | ✅ CM 3.4.3 | ✅ | DS Access ▸ Directory Service Changes |
| **5137** | Directory object created | ✅ AU 3.3.1 | | DS Access ▸ Directory Service Changes |
| **5141** | Directory object deleted | ✅ AU 3.3.1 | | DS Access ▸ Directory Service Changes |

> ⚠️ *Directory Service Changes* is **off by default** — 5136/5137/5141 will not fire until enabled.

## 7. Privilege Use

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4673** | A privileged service was called | ✅ AC 3.1.7 | | Privilege Use ▸ Sensitive Privilege Use |
| **4674** | Operation attempted on a privileged object | ✅ AC 3.1.7 | | Privilege Use ▸ Sensitive Privilege Use |

## 8. Policy Change

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4719** | System audit policy changed | ✅ AU 3.3.8 | | Policy Change ▸ Audit Policy Change |
| **4713** | Kerberos policy changed | ✅ CM 3.4.3 | | Policy Change ▸ Authentication Policy Change |
| **4716** | Trusted domain information modified | ✅ CM 3.4.3 | | Policy Change ▸ Authentication Policy Change |
| **4739** | Domain policy changed | ✅ CM 3.4.3 | | Policy Change ▸ Authentication Policy Change |

## 9. System Integrity

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **1102** | Security audit log cleared | ✅ AU 3.3.8 | | Always logged when the Security log is cleared |
| **4616** | System time changed | ✅ AU 3.3.7 | | System ▸ Security State Change |
| **7045** | A new service was installed | ✅ CM 3.4.3 | ✅ | System ▸ Security System Extension |

## 10. AD Certificate Services — *only if the DC is also a CA*

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4870** | Certificate revoked | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4882** | CA security permissions changed | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4885** | CA audit filter changed | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4887** | Certificate request approved / issued | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4888** | Certificate request denied | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4890** | Certificate manager settings changed | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |
| **4896** | Rows deleted from the certificate database | ✅ AU 3.3.1 | ✅ | Object Access ▸ Certification Services |

---

## CMMC Level context

| Level | Basis | Audit Logging Required? |
| :--- | :--- | :--- |
| **Level 1** — Basic Safeguarding of FCI | 15 reqs (FAR 52.204-21) | No |
| **Level 2** — Broad Protection of CUI | 110 reqs (**NIST SP 800-171 R2**) | **Yes — the entire AU family** |
| **Level 3** — Protection Against APTs | Level 2 + 24 reqs (NIST SP 800-172) | Reuses these logs; no new Event IDs |

> All DC events in this document satisfy **CMMC Level 2**.

---

## Configuration guardrails

1. Enable **Security Options ▸ "Audit: Force audit policy subcategory settings…"** (`SCENoApplyLegacyAuditPolicy = 1`).
2. Set the 9 legacy audit categories to **Not Defined** (not "No Auditing").
3. Enable **DS Access ▸ Directory Service Changes** — off by default.
4. Verify with **`auditpol.exe`**, not `rsop.msc`.
5. Link a **dedicated GPO to the Domain Controllers OU** — do not edit the Default Domain Controllers Policy.

---

## Data Collection Rule (DCR) — Sentinel ingestion

Enabling the audit policy above only **generates** the events on the DC. To land them in the `SecurityEvent` table, the Azure Monitor Agent needs a **DCR** with an XPath filter for these Event IDs.

> **XPath limits (Microsoft Learn):** a DCR allows **up to 20 EventID expressions per XPath query** and **up to 100 queries per rule**. We chunk at **10 Event IDs per line** to stay well within the limit and keep it readable — all **50** DC Event IDs fit in **5 lines**.

<details>
<summary><b>▸ xPathQueries snippet (drop into an existing DCR)</b></summary>

```json
"xPathQueries": [
  "Security!*[System[(EventID=1102) or (EventID=4616) or (EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or (EventID=4662) or (EventID=4672) or (EventID=4673) or (EventID=4674)]]",
  "Security!*[System[(EventID=4713) or (EventID=4716) or (EventID=4719) or (EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4728)]]",
  "Security!*[System[(EventID=4729) or (EventID=4730) or (EventID=4732) or (EventID=4733) or (EventID=4738) or (EventID=4739) or (EventID=4740) or (EventID=4741) or (EventID=4743) or (EventID=4753)]]",
  "Security!*[System[(EventID=4756) or (EventID=4757) or (EventID=4758) or (EventID=4763) or (EventID=4768) or (EventID=4771) or (EventID=4776) or (EventID=4870) or (EventID=4882) or (EventID=4885)]]",
  "Security!*[System[(EventID=4887) or (EventID=4888) or (EventID=4890) or (EventID=4896) or (EventID=5136) or (EventID=5137) or (EventID=5141) or (EventID=5168) or (EventID=7045) or (EventID=8004)]]"
]
```

</details>

<details>
<summary><b>▸ Full DCR definition (ready to deploy — replace the two placeholders)</b></summary>

```json
{
  "location": "<AZURE_REGION>",
  "kind": "Windows",
  "properties": {
    "dataSources": {
      "windowsEventLogs": [
        {
          "name": "cmmc-dc-securityevents",
          "streams": [ "Microsoft-SecurityEvent" ],
          "xPathQueries": [
            "Security!*[System[(EventID=1102) or (EventID=4616) or (EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or (EventID=4662) or (EventID=4672) or (EventID=4673) or (EventID=4674)]]",
            "Security!*[System[(EventID=4713) or (EventID=4716) or (EventID=4719) or (EventID=4720) or (EventID=4722) or (EventID=4723) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4728)]]",
            "Security!*[System[(EventID=4729) or (EventID=4730) or (EventID=4732) or (EventID=4733) or (EventID=4738) or (EventID=4739) or (EventID=4740) or (EventID=4741) or (EventID=4743) or (EventID=4753)]]",
            "Security!*[System[(EventID=4756) or (EventID=4757) or (EventID=4758) or (EventID=4763) or (EventID=4768) or (EventID=4771) or (EventID=4776) or (EventID=4870) or (EventID=4882) or (EventID=4885)]]",
            "Security!*[System[(EventID=4887) or (EventID=4888) or (EventID=4890) or (EventID=4896) or (EventID=5136) or (EventID=5137) or (EventID=5141) or (EventID=5168) or (EventID=7045) or (EventID=8004)]]"
          ]
        }
      ]
    },
    "destinations": {
      "logAnalytics": [
        {
          "workspaceResourceId": "<WORKSPACE_RESOURCE_ID>",
          "name": "sentinelWorkspace"
        }
      ]
    },
    "dataFlows": [
      {
        "streams": [ "Microsoft-SecurityEvent" ],
        "destinations": [ "sentinelWorkspace" ]
      }
    ]
  }
}
```

**Placeholders:** `<AZURE_REGION>` (e.g. `usgovvirginia`) · `<WORKSPACE_RESOURCE_ID>` = full resource ID of the Sentinel Log Analytics workspace.

</details>

> **Tip:** Validate any XPath line locally before deploying:
> ```powershell
> Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4662)]]' -MaxEvents 1
> ```
> Returns an event = valid · "No events found" = valid but none present yet · "query is invalid" = fix syntax.

---

## Sources

- [Configure Windows event auditing (Defender for Identity)](https://learn.microsoft.com/defender-for-identity/deploy/configure-windows-event-collection)
- [Advanced Audit Policy Configuration (AD DS)](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Windows security baseline — System Audit Policies](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows)
- [Collect Windows events with Azure Monitor Agent (XPath filtering)](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection-windows-events)
- [Azure Monitor service limits — Data collection rules](https://learn.microsoft.com/azure/azure-monitor/fundamentals/service-limits#data-collection-rules)
- [DoD CIO — About CMMC](https://dodcio.defense.gov/cmmc/About/)
- [Cyberlorians NIST Framework Dashboard](https://cyberlorians.github.io/nistframework/)
