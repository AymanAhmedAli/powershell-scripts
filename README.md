# 🔷 PowerShell Security Scripts

PowerShell scripts for Active Directory security auditing and IT automation — built from real-world penetration test findings.

> ⚠️ All scripts support `WhatIf` mode. Always test before applying in production.

---

## 📂 Audit Scripts

Read-only scripts that check and report — no changes made.

| Script | Description |
|--------|-------------|
| `ad_health_check.ps1` | Full AD health report — users, groups, password policy, security misconfigs |
| `disable_inactive_users.ps1` | Detects and disables users inactive 30+ days — safelist supported |
| `dc_security_check.ps1` | Checks DC security misconfigurations |
| `local_admin_audit.ps1` | Audits local admins across all domain computers — exports CSV |
| `security_audit.ps1` | Comprehensive audit based on pentest findings — Critical, High, Medium |

---

## 🔧 Fix Scripts

Remediation scripts — all support `WhatIf` mode for safe preview.

| Script | Finding | Severity | Impact |
|--------|---------|----------|--------|
| `fixes/fix_machine_quota.ps1` | Sets Machine Account Quota to 0 | 🔴 Critical | ✅ Zero |
| `fixes/fix_schema_admins.ps1` | Removes non-essential Schema Admins members | 🔴 Critical | ✅ Zero |
| `fixes/fix_recycle_bin.ps1` | Enables AD Recycle Bin (irreversible) | 🔴 Critical | ✅ Positive |
| `fixes/fix_password_policy.ps1` | Enforces 12+ char passwords + lockout | 🔴 Critical | ⚠️ Medium |
| `fixes/fix_audit_policy.ps1` | Enables advanced audit policy on DCs | 🟠 High | ✅ Low |
| `fixes/fix_print_spooler.ps1` | Disables Print Spooler on all DCs | 🔴 Critical | ⚠️ Medium |
| `fixes/fix_delegation.ps1` | Flags admin accounts sensitive/cannot delegate | 🔴 Critical | ✅ Zero |
| `fixes/fix_protected_users.ps1` | Adds admin accounts to Protected Users group | 🔴 Critical | ⚠️ Medium |
| `fixes/fix_ldap_signing.ps1` | Enforces LDAP signing + channel binding (3-phase) | 🟡 Medium | ⚠️ High |
| `fixes/fix_ad_subnets.ps1` | Adds missing DC subnets to AD Sites and Services | 🟡 Medium | ✅ Zero |
| `fixes/fix_krbtgt_rotation.ps1` | Rotates krbtgt password (run twice, 10h apart) | 🔴 Critical | ⚠️ High |
| `fixes/fix_laps.ps1` | Deploys Windows LAPS for local admin passwords | 🟡 Medium | ⚠️ Medium |

---

## ⚠️ WhatIf Mode

All fix scripts include a `$WhatIf` flag:

```powershell
$WhatIf = $true   # Preview only — no changes made
$WhatIf = $false  # Apply the fix
```

**Always run WhatIf first!**

---

## 📊 Recommended Rollout Order

Week 1 — Zero Impact (safe to apply immediately):
fix_machine_quota.ps1
fix_schema_admins.ps1
fix_recycle_bin.ps1
fix_audit_policy.ps1
fix_delegation.ps1
fix_ad_subnets.ps1

Week 2 — Requires validation:
fix_print_spooler.ps1 → verify no DC-based printing
fix_password_policy.ps1 → announce to users first
fix_protected_users.ps1 → test legacy apps first

Week 3-4 — Requires audit period:
fix_ldap_signing.ps1 → run Phase 1 for 2 weeks first
fix_krbtgt_rotation.ps1 → maintenance window, run twice
fix_laps.ps1 → requires LAPS MSI on older systems


---

## 🛠️ Requirements

- Windows Server 2016+
- PowerShell 5.1+
- RSAT Active Directory module
- Domain Admin privileges
- WinRM enabled (for remote computer scripts)

---

## 👤 Author

**Ayman Ahmed** — IT Specialist | Network Security

[![GitHub](https://img.shields.io/badge/GitHub-AymanAhmedAli-black?style=flat&logo=github)](https://github.com/AymanAhmedAli)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=flat&logo=linkedin)](https://www.linkedin.com/in/aymanahmedali/)
