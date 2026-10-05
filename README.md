# sentinel-table-retention

`Set-SentinelTableRetention.ps1` sets **analytics retention** and **total retention** on the Microsoft Sentinel tables of a workspace in one run. The default is 90 days analytics and 365 days total. The part beyond analytics retention is long-term retention, which Sentinel treats as data lake retention.

It is built for Microsoft Sentinel in the Defender portal (unified SOC), where a workspace can hold several hundred tables and clicking through them is not practical.

> **Disclaimer.** The script changes retention settings, which changes cost and, when shortened, deletes data. Always run it with `-WhatIf` first and review the list. It is provided as is, without warranty.

## Requirements

- **PowerShell 7 or newer.** Windows PowerShell 5.1 is not supported.
- **Azure RBAC** on the Sentinel workspace: **Log Analytics Contributor**, assigned at the workspace scope. It is the smallest built-in role that grants `tables/read`, `tables/write` and `workspaces/query/read`. If sign-in reports no subscription, the account may also need Reader on the resource group or subscription.
- **Internet access** to the PowerShell Gallery on first run.

No manual module setup is needed. The script installs `Az.Accounts` (2.0.0 or newer) for the current user if it is missing, and signs in with `Connect-AzAccount` if the current session is not in the requested tenant. Sign-in is interactive.

## Usage

Dry run (changes nothing):

```powershell
./Set-SentinelTableRetention.ps1 `
    -TenantId contoso.onmicrosoft.com `
    -SubscriptionId 00000000-0000-0000-0000-000000000000 `
    -ResourceGroupName rg-sentinel `
    -WorkspaceName log-sentinel `
    -WhatIf
```

Apply (lists the planned changes, then asks once for the whole set):

```powershell
./Set-SentinelTableRetention.ps1 `
    -TenantId contoso.onmicrosoft.com `
    -SubscriptionId 00000000-0000-0000-0000-000000000000 `
    -ResourceGroupName rg-sentinel `
    -WorkspaceName log-sentinel
```

If `-TenantId` is omitted, the script prompts for it. Use `-Confirm:$false` to skip the prompt.

### Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-TenantId` | prompt | Tenant GUID or domain. A domain name always triggers a sign-in. |
| `-SubscriptionId` | required | Subscription that contains the workspace. |
| `-ResourceGroupName` | required | Resource group of the workspace. |
| `-WorkspaceName` | required | Log Analytics workspace with Sentinel enabled. |
| `-AnalyticsRetentionInDays` | `90` | Analytics (interactive) retention. The script accepts 30 to 730. |
| `-TotalRetentionInDays` | `365` | Total retention, must be at least the analytics value. The script accepts up to 4383. |
| `-ExcludeTable` | none | Table names to skip. Wildcards allowed. Wins over `-IncludeTable`. |
| `-IncludeTable` | none | Extra tables to bring into scope. Wildcards allowed. |
| `-SkipIngestedTables` | off | Do not select tables only because they received data in the last 90 days. |
| `-AllowDecrease` | off | Also patch tables whose current retention is higher than the target. |
| `-PassThru` | off | Return the per-table result objects. |

### Output

The script prints the planned changes and a summary as tables:

```
Planned changes in 'log-sentinel':

Table     Source CurrentAnalytics CurrentTotal NewAnalytics NewTotal
-----     ------ ---------------- ------------ ------------ --------
AlertInfo Core                 90           90           90      365

Summary for 'log-sentinel':

Status           Tables
------           ------
AlreadyCompliant    152
Skipped             695
Updated               1
```

| Status | Meaning |
| --- | --- |
| `Updated` | ARM confirmed the change (HTTP 200). |
| `Accepted` | ARM accepted it asynchronously (HTTP 202). Run again, it reports `AlreadyCompliant` once applied. |
| `AlreadyCompliant` | Already at the requested values. |
| `Skipped` | Out of scope or excluded. With `-PassThru` the `Reason` column says why. |
| `WhatIf` / `Declined` | Planned but not applied (dry run or answered no). |
| `Failed` | The API returned an error. The message is in `Reason`, and the run continues with the other tables. |

## Which tables are in scope

The Defender portal shows a **Table type** (Sentinel, XDR, Custom) per table. No documented API exposes that value, so the script reproduces the portal's Sentinel list as closely as the supported APIs allow. A table is in scope when at least one of these is true (shown in the `Source` column):

| Source | Signal |
| --- | --- |
| `Core` | Member of the *Microsoft Sentinel* or *Microsoft Sentinel UEBA* table group from the Log Analytics metadata API (`GET .../api/metadata`). Falls back to `schema.solutions` if that call fails. |
| `Custom` | Custom log table (`tableType = CustomLog`, `_CL`). |
| `Ingested` | Received data in the last 90 days (`Usage` table). Turn off with `-SkipIngestedTables`. |
| `Include` | Matches `-IncludeTable`. |

In scope tables are **patched** only if all of these also hold:

- Plan is `Analytics`. Basic, Auxiliary and data lake tier tables are skipped.
- Not a search job or restore table (`_SRCH`, `_RST`).
- Not in an exclusion group (below) and not matched by `-ExcludeTable`.
- The change does not shorten an existing retention value (unless `-AllowDecrease`).
- The values are not already at the target.

### Exclusion groups (always skipped)

| Group | Why |
| --- | --- |
| XDR-only tables (for example `ExposureGraph*`, `EntraIdSignInEvents`, `BehaviorInfo`, `DeviceBehavior*`, `DeviceCustom*`) | The portal reports them as type XDR. They cannot be managed through table management. |
| `DeviceTvm*` | Defender Vulnerability Management data is not ingested into Sentinel. |
| Data lake candidates: the Defender advanced hunting tables `Device*` (MDE), `Email*`, `UrlClickEvents` (MDO) and `CloudAppEvents` (MDA) | Raising analytics retention would copy the data into the Sentinel analytics tier and cost ingestion fees. Set them to **Data lake tier** in the portal instead (see below). |

The lists are defined at the top of the script (`$XdrOnlyTables`, `$NotIngestedTables`, `$DataLakeCandidateTables`). Check them against the portal's Table type column before running for real.

### Known limits of the scope selection

- The selection is **inferred**, not an official Microsoft list. On the one workspace it was measured on, it found 173 of 178 portal tables and selected none the portal does not list. Other tenants were not verified.
- The portal also counts ordinary Azure tables such as `AzureDiagnostics` or `SigninLogs` as Sentinel tables when they hold data. In a workspace shared with Azure Monitor workloads, the `Ingested` signal therefore also selects those tables. Use `-SkipIngestedTables` and `-ExcludeTable` to limit the scope, and read the `-WhatIf` list.
- A table that is Sentinel in the portal but has no data and is not in the Sentinel table groups needs `-IncludeTable`.

## Data lake tier for Defender advanced hunting tables (manual)

The script does not change the tier. Configure these tables in the portal:

**Defender portal > Microsoft Sentinel > Configuration > Tables > the table > Manage table > Data lake tier > set retention > Save**

Supported tables: `DeviceInfo`, `DeviceNetworkInfo`, `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceRegistryEvents`, `DeviceLogonEvents`, `DeviceImageLoadEvents`, `DeviceEvents`, `DeviceFileCertificateInfo` (MDE, needs a licence), `EmailAttachmentInfo`, `EmailEvents`, `EmailPostDeliveryEvents`, `EmailUrlInfo`, `UrlClickEvents` (MDO) and `CloudAppEvents` (MDA). Hunting keeps 30 days in the XDR tier regardless. Defender for Identity tables are not supported yet.

Doing this needs *Microsoft Sentinel Contributor* and *Log Analytics Contributor* on the workspace, or Defender unified RBAC `Data (manage)`.

Background: the ARM Tables API (api-version 2023-09-01) rejects `plan: Auxiliary`. Newer api-versions (2025-07-01 and later) accepted it in a test on one table, but that is undocumented and the script does not use it.

## Behavior and cost notes

- Shortening total retention keeps data for another 30 days before removal. The script skips such tables unless `-AllowDecrease` is set.
- Longer analytics retention costs more, especially on high-volume tables. Microsoft's docs disagree on whether the free 90 days apply to all workspace data or only to Sentinel solution tables. Check your own billing.
- Tables whose lake support is "No" in the Azure Monitor table reference (for example `Usage`, `Heartbeat`, `Operation`, `Watchlist`) can still use 90/365. "No" only means they cannot be switched to the lake-only tier. Whether the long-term part is queryable through data lake KQL for them is not documented.
- The script sends one PATCH per table and retries throttling (429), conflicts (409), server errors (5xx) and transport errors. One failed table does not stop the run.

## References

- [Manage data tiers and retention in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview)
- [Configure table settings in Microsoft Sentinel](https://learn.microsoft.com/en-us/azure/sentinel/manage-table-tiers-retention)
- [Data lake tier ingestion for Defender advanced hunting tables](https://techcommunity.microsoft.com/blog/microsoftsentinelblog/data-lake-tier-ingestion-for-microsoft-defender-advanced-hunting-tables-is-now-g/4494206)
- [Azure Monitor Logs table reference](https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables-index)

## License

Add a license of your choice before publishing (MIT is a common default).
