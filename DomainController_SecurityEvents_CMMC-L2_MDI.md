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
| **MP** | Media Protection |
| **SC** | System and Communications Protection |
| **SI** | System and Information Integrity |

> Both columns use the same **✅** marker so they read consistently at a glance.

---

## GPO base path

All subcategories live under one path — only the last two segments change per event:

```
Computer Configuration ▸ Policies ▸ Windows Settings ▸ Security Settings
  ▸ Advanced Audit Policy Configuration ▸ Audit Policies ▸ <Category> ▸ <Subcategory>
```

Configure **Success and Failure** for every subcategory below.

> ⚡ **Shortcut — apply all subcategories at once.** Instead of clicking each one, use the ready-made backup file [`AdvancedAudit_DC_CMMC-L2.csv`](AdvancedAudit_DC_CMMC-L2.csv). From an **elevated** prompt on the DC:
> ```powershell
> auditpol /restore /file:AdvancedAudit_DC_CMMC-L2.csv
> ```
> Or drop it in a GPO at `...\SYSVOL\<domain>\Policies\<GUID>\Machine\Microsoft\Windows NT\Audit\audit.csv`. Verify with `auditpol /get /category:*`.

---

## 1. Account Logon — Kerberos & NTLM

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4768** | Kerberos TGT requested | ✅ AU 3.3.1 | | Account Logon ▸ Kerberos Authentication Service |
| **4771** | Kerberos pre-authentication failed | ✅ IA 3.5.2 | | Account Logon ▸ Kerberos Authentication Service |
| **4769** | Kerberos service ticket requested (**Kerberoasting**) | ✅ AU 3.3.1 | | Account Logon ▸ Kerberos Service Ticket Operations |
| **4770** | Kerberos service ticket renewed | ✅ AU 3.3.1 | | Account Logon ▸ Kerberos Service Ticket Operations |
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
| **4627** | Group membership evaluated at logon | ✅ AU 3.3.1 | ✅ | Logon/Logoff ▸ Audit Group Membership |
| **4778** | Session reconnected (RDP) | ✅ AU 3.3.1 | | Logon/Logoff ▸ Other Logon/Logoff Events |
| **4779** | Session disconnected (RDP) | ✅ AU 3.3.1 | | Logon/Logoff ▸ Other Logon/Logoff Events |
| **4800** | Workstation locked | ✅ AC 3.1.10 | | Logon/Logoff ▸ Other Logon/Logoff Events |
| **4801** | Workstation unlocked | ✅ AC 3.1.10 | | Logon/Logoff ▸ Other Logon/Logoff Events |

> ➕ Also enable **Logon/Logoff ▸ Audit Account Lockout** (Success and Failure). It records failed logons caused by a locked account (event **4625** with lockout status) — supporting **AC 3.1.8** alongside 4740 (Account Management).

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
| **4782** | Password hash of an account was accessed | ✅ AU 3.3.1 | | Account Management ▸ Other Account Management Events |

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
| **4670** | Permissions on an object changed | ✅ AC 3.1.5 | | Policy Change ▸ Authorization Policy Change |
| **4704** | User right assigned | ✅ AC 3.1.5 | | Policy Change ▸ Authorization Policy Change |
| **4705** | User right removed | ✅ AC 3.1.5 | | Policy Change ▸ Authorization Policy Change |
| **4946** | Windows Firewall rule added | ✅ CM 3.4.3 | | Policy Change ▸ MPSSVC Rule-Level Policy Change |
| **4947** | Windows Firewall rule modified | ✅ CM 3.4.3 | | Policy Change ▸ MPSSVC Rule-Level Policy Change |
| **4948** | Windows Firewall rule deleted | ✅ CM 3.4.3 | | Policy Change ▸ MPSSVC Rule-Level Policy Change |

## 9. System Integrity

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **1102** | Security audit log cleared | ✅ AU 3.3.8 | | Always logged when the Security log is cleared |
| **4616** | System time changed | ✅ AU 3.3.7 | | System ▸ Security State Change |
| **7045** | A new service was installed | ✅ CM 3.4.3 | ✅ | System ▸ Security System Extension |
| **4697** | A service was installed (Security log) | ✅ CM 3.4.3 | ✅ | System ▸ Security System Extension |
| **4612** | Audit messages dropped (audit queue full) | ✅ AU 3.3.1 | | System ▸ System Integrity |
| **5038** | Code integrity — image hash invalid | ✅ SI 3.14.1 | | System ▸ System Integrity |
| **5025** | Windows Firewall service stopped | ✅ SC 3.13.1 | | System ▸ Other System Events |

> Enable the **full System category** (all Success and Failure): Security State Change, Security System Extension, System Integrity, Other System Events, and IPsec Driver. All are **low-volume, high-integrity** signals. IPsec Driver is included for baseline parity (SC 3.13.x) even on non-IPsec DCs — it rarely fires but costs nothing.

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

> 🚫 **Plain DC (not a CA)?** Skip this whole category — **Object Access requires nothing** for CMMC on a non-CA DC. The backup file [`AdvancedAudit_DC_CMMC-L2.csv`](AdvancedAudit_DC_CMMC-L2.csv) **excludes** Certification Services for that reason. If the DC **is** a CA, set **Object Access ▸ Certification Services** to Success and Failure (GUI) or add this line to the CSV:
> ```
> ,System,Audit Certification Services,{0cce9221-69ae-11d9-bed3-505054503030},Success and Failure,,3
> ```

---

## 11. Object Access — Removable Storage

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4663** | Attempt to access a removable storage object | ✅ MP 3.8.7 | | Object Access ▸ Removable Storage |

> Enabled because removable-media access is a **Media Protection** control (3.8.7). Low volume, and — unlike *Audit File System* — it needs **no SACLs** to generate events.

---

## 12. Detailed Tracking — Process & Device Activity

| Event | Description | CMMC | MDI | GPO Subcategory |
| :---: | :--- | :--- | :---: | :--- |
| **4688** | A new process was created | ✅ AU 3.3.1 | | Detailed Tracking ▸ Process Creation |
| **6416** | A new external device was recognized (PnP) | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |
| **6419** | A request was made to disable a device | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |
| **6420** | A device was disabled | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |
| **6421** | A request was made to enable a device | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |
| **6422** | A device was enabled | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |
| **6423** | Device installation forbidden by system policy | ✅ MP 3.8.7 | | Detailed Tracking ▸ PNP Activity |

> 🔑 **Enable command-line capture.** Turn on **Administrative Templates ▸ System ▸ Audit Process Creation ▸ "Include command line in process creation events"** so **4688** records the full command line — essential for detection and for CMMC AU coverage. Process Creation and PNP Activity are set to **Success** (failures are not generated).

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

## Deploying the audit policy from the CSV

The backup file [`AdvancedAudit_DC_CMMC-L2.csv`](AdvancedAudit_DC_CMMC-L2.csv) holds the **complete desired audit state** for a plain (non-CA) Domain Controller — **29 subcategories**. Deploy it one of two ways.

> ⚠️ **`auditpol /restore` is a full replace.** Every subcategory *not* in the file is reset to **No Auditing**. This CSV **is** the entire baseline, so that is the intended behavior — do not merge it with a partial file.

### Option A — Single DC (`auditpol`)

From an **elevated** prompt on the DC:

```powershell
# Apply the full baseline
auditpol /restore /file:AdvancedAudit_DC_CMMC-L2.csv

# Confirm every subcategory took effect
auditpol /get /category:*
```

### Option B — All DCs (Group Policy)

1. Create/edit a GPO **linked to the Domain Controllers OU** (not the Default Domain Controllers Policy).
2. Copy the file into that GPO's audit folder in SYSVOL, renamed **`audit.csv`**:
   ```
   \\<domain>\SYSVOL\<domain>\Policies\{GPO-GUID}\Machine\Microsoft\Windows NT\Audit\audit.csv
   ```
3. Enable **Security Options ▸ "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"** = **Enabled** (`SCENoApplyLegacyAuditPolicy = 1`).
4. Run `gpupdate /force` on the DCs, then verify with `auditpol /get /category:*`.

> The CSV **excludes** *Certification Services* (CA-only). If a DC is also a CA, add the line from [§10](#10-ad-certificate-services--only-if-the-dc-is-also-a-ca) to the CSV **before** deploying.
>
> 🔑 Two signals are **not** Advanced Audit subcategories and must be set separately: enable **Administrative Templates ▸ System ▸ Audit Process Creation ▸ "Include command line in process creation events"** (for 4688) and **Security Options ▸ "Restrict NTLM: Audit NTLM authentication in this domain"** (for 8004 / 5168).

---

## Data Collection Rule (DCR) — Sentinel ingestion

Enabling the audit policy above only makes the events appear **on the DC**. To land them in the `SecurityEvent` table in Sentinel, the Azure Monitor Agent (AMA) needs a **DCR** that says which Event IDs to collect.

You build this entirely in the **Sentinel portal** — no scripts, no CLI. Just paste the XPath lines below.

### How it works (2 steps)

1. **Deploy the Common set first** via the built-in **Windows Security Events via AMA** connector (choose the **Common** event set). This creates the DCR and wires your DCs to it.
2. **Edit that same DCR** → switch collection to **Custom** → paste the **Domain Controller XPath lines** below to add the DC / CMMC / MDI Event IDs on top of Common.

> 💡 **One XPath per box.** The portal has no bulk paste — paste **one line**, click **Add**, repeat. No quotes, no commas, no `"xPathQueries": [ ]` wrapper. Keep each line to **≤ 20 Event IDs** (the portal rejects more).

### Step-by-step (portal)

1. In **Microsoft Sentinel** → **Content hub**, install/open **Windows Security Events via AMA**.
2. Select **Open connector page** → **+ Create data collection rule**.
3. Name it (e.g. `DCR-DomainControllers-CMMC-L2`), pick your subscription / resource group.
4. **Resources** tab → add your Domain Controllers (Azure or Azure Arc–enabled).
5. **Collect** tab → choose **Custom**.
6. Paste each XPath line below, clicking **Add** after each one.
7. **Review + create.**

Events start flowing to `SecurityEvent` within a few minutes.

### 📋 Domain Controller Event IDs — copy/paste (4 lines)

Paste these four lines into the **Custom** XPath box, one at a time:

```
Security!*[System[((EventID=1102) or (EventID=4612) or (EventID=4616) or (EventID=4624) or (EventID=4625) or (EventID=4634) or (EventID=4647) or (EventID=4662) or (EventID=4663) or (EventID=4670) or (EventID=4672) or (EventID=4673) or (EventID=4674) or (EventID=4704) or (EventID=4705) or (EventID=4713) or (EventID=4716) or (EventID=4719) or (EventID=4720) or (EventID=4722))]]
```

```
Security!*[System[((EventID=4723) or (EventID=4724) or (EventID=4725) or (EventID=4726) or (EventID=4728) or (EventID=4729) or (EventID=4730) or (EventID=4732) or (EventID=4733) or (EventID=4738) or (EventID=4739) or (EventID=4740) or (EventID=4741) or (EventID=4743) or (EventID=4753) or (EventID=4946) or (EventID=4947) or (EventID=4948) or (EventID=4697))]]
```

```
Security!*[System[((EventID=4627) or (EventID=4756) or (EventID=4757) or (EventID=4758) or (EventID=4763) or (EventID=4768) or (EventID=4771) or (EventID=4776) or (EventID=4778) or (EventID=4779) or (EventID=4800) or (EventID=4801) or (EventID=5025) or (EventID=5038) or (EventID=5136) or (EventID=5137) or (EventID=5141) or (EventID=5168) or (EventID=7045) or (EventID=8004))]]
```

```
Security!*[System[((EventID=4688) or (EventID=4769) or (EventID=4770) or (EventID=4782) or (EventID=6416) or (EventID=6419) or (EventID=6420) or (EventID=6421) or (EventID=6422) or (EventID=6423))]]
```

> ⚠️ **Line 4 is higher-volume** (Process Creation 4688, Kerberos TGS 4769). If **Defender for Identity / for Endpoint** is deployed you can drop it — MDI detects Kerberoasting and process attacks natively. Include it if you want the raw events in Sentinel.

### 📋 Optional — AD Certificate Services (only if the DC is also a CA)

Add this **5th line** only when the DC runs AD CS:

```
Security!*[System[((EventID=4870) or (EventID=4882) or (EventID=4885) or (EventID=4887) or (EventID=4888) or (EventID=4890) or (EventID=4896))]]
```

### ✅ Verify

**In Sentinel** — confirm events are landing:

```kql
SecurityEvent
| where TimeGenerated > ago(1h)
| summarize Count = count() by EventID
| sort by Count desc
```

**On the DC** — validate a single XPath line:

```powershell
Get-WinEvent -LogName Security -FilterXPath '*[System[(EventID=4662)]]' -MaxEvents 1
```

Returns an event = valid · "No events found" = valid but none present yet · "query is invalid" = fix syntax.

---

## Sources

- [Configure Windows event auditing (Defender for Identity)](https://learn.microsoft.com/defender-for-identity/deploy/configure-windows-event-collection)
- [Advanced Audit Policy Configuration (AD DS)](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Windows security baseline — System Audit Policies](https://learn.microsoft.com/azure/governance/policy/samples/guest-configuration-baseline-windows)
- [Collect Windows events with Azure Monitor Agent (XPath filtering)](https://learn.microsoft.com/azure/azure-monitor/vm/data-collection-windows-events)
- [Azure Monitor service limits — Data collection rules](https://learn.microsoft.com/azure/azure-monitor/fundamentals/service-limits#data-collection-rules)
- [DoD CIO — About CMMC](https://dodcio.defense.gov/cmmc/About/)
- [Cyberlorians NIST Framework Dashboard](https://cyberlorians.github.io/nistframework/)
