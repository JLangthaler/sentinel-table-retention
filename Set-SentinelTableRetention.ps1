<#
.SYNOPSIS
    Sets analytics and total retention on the Microsoft Sentinel tables of a workspace.

.DESCRIPTION
    Enumerates the tables of a Microsoft Sentinel (Log Analytics) workspace through the
    Azure Resource Manager Tables API and sets
      - retentionInDays       (analytics / interactive retention)
      - totalRetentionInDays  (total retention, remainder is kept in the Sentinel data lake)
    on every table that is in scope.

    Scope
    -----
    The Defender portal shows a "Table type" (Sentinel / XDR / Custom) per table. That value is
    NOT exposed by any documented API. The script reproduces the portal's Sentinel list as
    closely as the supported APIs allow. A table is IN SCOPE when at least one of these is true
    (the -WhatIf output shows which one, in the Source column):
      - Core      Table belongs to the 'Microsoft Sentinel' or 'Microsoft Sentinel UEBA' table
                  group of the Log Analytics metadata API (GET .../api/metadata). If that call
                  fails the script falls back to schema.solutions of the Tables API
      - Custom    Custom log table (tableType CustomLog, _CL)
      - Ingested  Table received data in the last 90 days (Usage table). Disable with
                  -SkipIngestedTables. This matches the portal, which also lists Azure tables
                  such as AzureDiagnostics or SigninLogs when they hold data. In a workspace
                  shared with other workloads it therefore also selects Azure Monitor tables
      - Include   Table matches -IncludeTable
    Measured on one lab workspace this reproduced the portal's Sentinel and Custom tables
    (173 of 178 found, none wrongly selected). Other tenants have not been verified, so always
    review the -WhatIf output first.

    An in-scope table is PATCHED when ALL of these are true:
      - plan is 'Analytics' (Basic, Auxiliary and Data lake tier tables are skipped)
      - name does not end in _SRCH or _RST (search job / restore tables)
      - it is not in one of the exclusion groups below
      - it is not excluded with -ExcludeTable
      - the change does not shorten an existing retention value (unless -AllowDecrease)
      - the retention values are not already set to the requested values

    Exclusion groups (always skipped):
      1. XDR-only tables       Tables the Defender portal reports as table type 'XDR'. Their
                               retention cannot be managed through table management.
      2. Not-ingested tables   DeviceTvm* tables. Defender Vulnerability Management data is
                               not streamed to Sentinel.
      3. Data lake candidates  Defender advanced hunting tables that support lake-tier ingestion
                               (MDE, MDO, MDA). Raising analytics retention for these puts a copy
                               of the data into the Sentinel analytics tier and causes
                               analytics ingestion cost. Set them to 'Data lake tier' in the
                               Defender portal instead (see NOTES).

    The lists are maintained inside the script (see $XdrOnlyTables, $NotIngestedTables,
    $DataLakeCandidateTables). Verify them against the Table type column in the Defender portal
    (Microsoft Sentinel > Configuration > Tables) before running with real changes.

    Confirmation
    ------------
    The script asks once for the whole set of changes (not once per table). The list of
    planned changes is printed before the prompt. -WhatIf prints the list and changes nothing.
    Use -Confirm:$false to run without a prompt.

.PARAMETER TenantId
    Entra tenant (GUID or domain name) that owns the subscription. If omitted, the script
    prompts for it. The script signs in to this tenant (Connect-AzAccount) when the current
    Az session is not already in it. A domain name always triggers a sign-in.

.PARAMETER SubscriptionId
    Subscription that contains the Sentinel workspace.

.PARAMETER ResourceGroupName
    Resource group that contains the Sentinel workspace.

.PARAMETER WorkspaceName
    Name of the Log Analytics workspace that Sentinel is enabled on.

.PARAMETER AnalyticsRetentionInDays
    Analytics (interactive) retention. The script accepts 30 to 730 days. Default: 90.

.PARAMETER TotalRetentionInDays
    Total retention including the data lake. Must be >= AnalyticsRetentionInDays. The script
    accepts up to 4383 days (12 years). Default: 365.

.PARAMETER ExcludeTable
    Additional table names to skip. Wildcards are supported. Wins over -IncludeTable.

.PARAMETER IncludeTable
    Additional table names to bring into scope that the automatic selection does not find
    (for example a Sentinel table without data in the last 90 days). Wildcards are supported.
    The exclusion groups still apply.

.PARAMETER SkipIngestedTables
    Do not add tables to the scope only because they received data in the last 90 days.
    Use this in workspaces shared with Azure Monitor workloads to limit the scope to the
    Sentinel table groups and custom tables.

.PARAMETER AllowDecrease
    Also patch tables whose current analytics or total retention is HIGHER than the requested
    value. Without this switch such tables are skipped, because shortening total retention
    deletes data that is older than the new value.

.PARAMETER PassThru
    Returns the per-table result objects instead of only writing a summary.

.EXAMPLE
    .\Set-SentinelTableRetention.ps1 -TenantId contoso.onmicrosoft.com `
        -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-sentinel -WorkspaceName log-sentinel -WhatIf

    Dry run. Signs in to the tenant, reads the tables and lists what would change.
    Nothing is modified. Without -TenantId the script prompts for it.

.EXAMPLE
    .\Set-SentinelTableRetention.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-sentinel -WorkspaceName log-sentinel

    Sets 90 days analytics / 365 days total retention on all in-scope tables. Lists the planned
    changes and asks once before patching.

.EXAMPLE
    .\Set-SentinelTableRetention.ps1 -SubscriptionId 00000000-0000-0000-0000-000000000000 `
        -ResourceGroupName rg-sentinel -WorkspaceName log-sentinel `
        -ExcludeTable 'AzureDiagnostics', 'CommonSecurityLog' -Confirm:$false

    Skips two high-volume tables and does not prompt.

.NOTES
    Requirements
      - PowerShell 7 or newer (Windows PowerShell 5.1 is not supported), with access to the
        PowerShell Gallery on first run
      - Log Analytics Contributor on the workspace (tables/read, tables/write and
        workspaces/query/read for the table metadata and the Usage query)
      No manual setup is needed. The script installs the Az.Accounts module (2.0.0 or newer)
      for the current user if it is missing or too old (also under -WhatIf), and signs in with
      Connect-AzAccount when the current Az session is not in the requested tenant. Sign-in is
      interactive.

    Data lake tier for Defender advanced hunting tables (manual step)
      The script does not change the tier. The documented route is the Defender portal. (ARM
      api-version 2023-09-01 rejects plan 'Auxiliary'. A lab test with api-version 2025-07-01
      accepted it on one table, but that is undocumented and not used here.) Configure these
      tables in the portal:
        Defender portal > Microsoft Sentinel > Configuration > Tables > <table> >
        Manage table > Data lake tier > set retention > Save
      Supported tables: DeviceInfo, DeviceNetworkInfo, DeviceProcessEvents, DeviceNetworkEvents,
      DeviceFileEvents, DeviceRegistryEvents, DeviceLogonEvents, DeviceImageLoadEvents,
      DeviceEvents, DeviceFileCertificateInfo (MDE, requires licence), EmailAttachmentInfo,
      EmailEvents, EmailPostDeliveryEvents, EmailUrlInfo, UrlClickEvents (MDO) and
      CloudAppEvents (MDA). MDI tables are not supported yet. Hunting keeps 30 days in the
      XDR tier regardless of this setting.

    Behavior
      - Shortening total retention keeps data for another 30 days before it is removed. The
        script skips such tables unless -AllowDecrease is set.
      - Cost: longer analytics retention increases cost, especially for high-volume tables.
        Analytics retention of 90 days is free of storage charge for Sentinel solution tables,
        everything beyond is billed. Total retention beyond analytics retention is billed at
        data lake rates.
      - Status 'Accepted' means ARM accepted the change asynchronously (HTTP 202). Verify the
        result in the Defender portal or with a second run (it reports 'AlreadyCompliant').
      - Tables that are not in the portal's table list may still be listed by the API.
        They are patched like any other Analytics table unless excluded.

    Reference
      https://learn.microsoft.com/en-us/azure/sentinel/manage-data-overview
      https://learn.microsoft.com/en-us/azure/sentinel/manage-table-tiers-retention
#>
#Requires -Version 7.0
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param (
    [ValidatePattern('^([0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}|(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,})$')]
    [string] $TenantId,

    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
    [string] $SubscriptionId,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $ResourceGroupName,

    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string] $WorkspaceName,

    [ValidateRange(30, 730)]
    [int] $AnalyticsRetentionInDays = 90,

    [ValidateRange(30, 4383)]
    [int] $TotalRetentionInDays = 365,

    [string[]] $ExcludeTable = @(),

    [string[]] $IncludeTable = @(),

    [switch] $SkipIngestedTables,

    [switch] $AllowDecrease,

    [switch] $PassThru
)

# Pinned to 3.0, the strictest version PowerShell defines today. 'Latest' can change meaning in newer releases.
Set-StrictMode -Version 3.0
$ErrorActionPreference = 'Stop'

if ($TotalRetentionInDays -lt $AnalyticsRetentionInDays) {
    throw "TotalRetentionInDays ($TotalRetentionInDays) must be greater than or equal to AnalyticsRetentionInDays ($AnalyticsRetentionInDays)."
}

$ApiVersion    = '2023-09-01'
$MinAzAccounts = [version] '2.0.0'
$MaxAttempts   = 5

# Group 1: tables the Defender portal reports as table type 'XDR' (not manageable).
# Wildcards allowed. Verify against the Table type column in the Defender portal.
$XdrOnlyTables = @(
    'CallActivityEvents'
    'ExposureGraph*'
    'ExposureRecommendations'
    'ConnectorStatusInfo'
    'ThreatIntelEntities'
    'EntraIdSignInEvents'
    'EntraIdSpnSignInEvents'
    'GraphAPIAuditEvents'
    'BehaviorInfo'
    'BehaviorEntities'
    'DeviceBehavior*'
    'DeviceCustom*'
)

# Group 2: Defender Vulnerability Management tables are not ingested into Sentinel.
$NotIngestedTables = @(
    'DeviceTvm*'
)

# Group 3: advanced hunting tables that support data lake tier ingestion.
# Configure these in the Defender portal as 'Data lake tier' (no API available).
$DataLakeCandidateTables = @(
    'DeviceInfo'
    'DeviceNetworkInfo'
    'DeviceProcessEvents'
    'DeviceNetworkEvents'
    'DeviceFileEvents'
    'DeviceRegistryEvents'
    'DeviceLogonEvents'
    'DeviceImageLoadEvents'
    'DeviceEvents'
    'DeviceFileCertificateInfo'
    'EmailAttachmentInfo'
    'EmailEvents'
    'EmailPostDeliveryEvents'
    'EmailUrlInfo'
    'UrlClickEvents'
    'CloudAppEvents'
)

function Test-NameMatch {
    [CmdletBinding()]
    param (
        [string]   $Name,
        [string[]] $Pattern
    )

    foreach ($p in $Pattern) {
        if ($Name -like $p) { return $true }
    }
    return $false
}

function Get-PropertyValue {
    # Reads a property without failing under StrictMode when it does not exist.
    [CmdletBinding()]
    param (
        $InputObject,
        [string] $Name
    )

    if ($null -eq $InputObject) { return $null }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($property) { return $property.Value }
    return $null
}

function Get-ErrorMessage {
    # Extracts the ARM error message, falls back to the raw body.
    [CmdletBinding()]
    param (
        [string] $Content
    )

    if ([string]::IsNullOrWhiteSpace($Content)) { return '(empty response)' }
    try {
        $message = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject ($Content | ConvertFrom-Json) -Name 'error') -Name 'message'
        if ($message) { return [string] $message }
    }
    catch {
        Write-Verbose "Response body is not JSON: $($_.Exception.Message)"
    }
    return $Content.Substring(0, [Math]::Min(300, $Content.Length))
}

function Invoke-ArmRequest {
    # Never throws. Retries throttling (429), server errors (5xx), conflicts (409) and transport
    # errors. Returns an object with StatusCode (0 = transport error) and Content.
    [CmdletBinding()]
    param (
        [ValidateSet('GET', 'POST', 'PATCH')]
        [string] $Method,
        [string] $Path,
        [string] $Payload
    )

    for ($attempt = 1; $attempt -le $MaxAttempts; $attempt++) {
        $params = @{
            Method      = $Method
            Path        = $Path
            WhatIf      = $false
            Confirm     = $false
            ErrorAction = 'Stop'
        }
        if ($Payload) { $params['Payload'] = $Payload }

        $delay = 5 * $attempt
        try {
            $response = Invoke-AzRestMethod @params
            $code     = [int] $response.StatusCode
            if ($code -ne 429 -and $code -ne 409 -and $code -lt 500) {
                return $response
            }

            $retryAfter = $null
            try { $retryAfter = @($response.Headers['Retry-After'])[0] } catch { $retryAfter = $null }
            if ($retryAfter -as [int]) { $delay = [Math]::Min([int] $retryAfter, 60) }
            $result = $response
        }
        catch {
            $result = [pscustomobject] @{
                StatusCode = 0
                Content    = $_.Exception.Message
            }
        }

        if ($attempt -eq $MaxAttempts) { return $result }
        Write-Verbose "Request failed with status $($result.StatusCode). Retrying in $delay s ($attempt/$MaxAttempts)."
        Start-Sleep -Seconds $delay
    }
}

function Initialize-AzSession {
    [CmdletBinding()]
    param (
        [string] $TenantId,
        [string] $SubscriptionId
    )

    # Preparing the session must happen even when the script runs with -WhatIf or -Confirm.
    $WhatIfPreference  = $false
    $ConfirmPreference = 'None'

    $module = Get-Module -ListAvailable -Name Az.Accounts |
        Where-Object { $_.Version -ge $MinAzAccounts } |
        Select-Object -First 1
    if (-not $module) {
        Write-Host "Az.Accounts $MinAzAccounts or newer not found. Installing for the current user ..."
        if (-not (Get-PSRepository -Name PSGallery -ErrorAction SilentlyContinue)) {
            Register-PSRepository -Default
        }
        Install-Module -Name Az.Accounts -MinimumVersion $MinAzAccounts -Scope CurrentUser -Repository PSGallery -Force -AllowClobber
    }
    Import-Module -Name Az.Accounts -MinimumVersion $MinAzAccounts

    # A tenant given as domain name cannot be compared to the context tenant ID, so it always signs in.
    $context  = Get-AzContext
    $inTenant = [bool] ($context -and (Get-PropertyValue -InputObject $context.Tenant -Name 'Id') -eq $TenantId)
    if (-not $inTenant) {
        Write-Host "Signing in to tenant $TenantId ..."
        $null = Connect-AzAccount -Tenant $TenantId -Subscription $SubscriptionId
    }
    elseif ((Get-PropertyValue -InputObject $context.Subscription -Name 'Id') -ne $SubscriptionId) {
        $null = Set-AzContext -Tenant $TenantId -Subscription $SubscriptionId
    }

    $context = Get-AzContext
    if (-not $context -or (Get-PropertyValue -InputObject $context.Subscription -Name 'Id') -ne $SubscriptionId) {
        throw "Could not select subscription $SubscriptionId in tenant $TenantId."
    }
    Write-Verbose "Using $($context.Account.Id) in tenant $($context.Tenant.Id), subscription $($context.Subscription.Name)."
}

if (-not $TenantId) {
    $TenantId = Read-Host -Prompt 'Tenant ID (GUID or domain, e.g. contoso.onmicrosoft.com)'
    $guid     = '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$'
    $domain   = '^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.[A-Za-z]{2,}$'
    if ($TenantId -notmatch $guid -and $TenantId -notmatch $domain) {
        throw "'$TenantId' is not a valid tenant ID or domain name."
    }
}

Initialize-AzSession -TenantId $TenantId -SubscriptionId $SubscriptionId

$basePath = "/subscriptions/$SubscriptionId/resourceGroups/$ResourceGroupName/providers/Microsoft.OperationalInsights/workspaces/$WorkspaceName/tables"

# Read all tables (follow paging)
$tables = [System.Collections.Generic.List[object]]::new()
$path   = "${basePath}?api-version=$ApiVersion"
while ($path) {
    $response = Invoke-ArmRequest -Method GET -Path $path
    if ($response.StatusCode -ne 200) {
        throw "Could not list tables ($($response.StatusCode)): $(Get-ErrorMessage -Content $response.Content)"
    }
    $body = $response.Content | ConvertFrom-Json
    foreach ($t in $body.value) { $tables.Add($t) }
    $path = $null
    $next = Get-PropertyValue -InputObject $body -Name 'nextLink'
    if ($next) {
        $path = ([uri] $next).PathAndQuery
    }
}
Write-Verbose "Found $($tables.Count) tables in workspace '$WorkspaceName'."

# Scope signal 1 (Core): Sentinel table groups of the Log Analytics metadata API
$workspacePath = $basePath -replace '/tables$', ''
$coreSet       = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
$response      = Invoke-ArmRequest -Method GET -Path "$workspacePath/api/metadata?api-version=2020-08-01"
$groups        = $null
if ($response.StatusCode -eq 200) {
    try { $groups = (Get-PropertyValue -InputObject ($response.Content | ConvertFrom-Json) -Name 'tableGroups') }
    catch { Write-Verbose "Could not parse metadata response: $($_.Exception.Message)" }
}
if ($groups) {
    foreach ($group in $groups) {
        if ((Get-PropertyValue -InputObject $group -Name 'name') -in 'SecurityInsights', 'BehaviorAnalyticsInsights') {
            foreach ($t in @(Get-PropertyValue -InputObject $group -Name 'tables')) { [void] $coreSet.Add(($t -replace '^t/', '')) }
        }
    }
}
if ($coreSet.Count -eq 0) {
    Write-Warning 'Sentinel table groups are not available from the metadata API. Falling back to the solutions listed on the tables.'
    foreach ($table in $tables) {
        $solutions = @(Get-PropertyValue -InputObject (Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $table -Name 'properties') -Name 'schema') -Name 'solutions')
        if ($solutions -contains 'SecurityInsights' -or $solutions -contains 'BehaviorAnalyticsInsights') { [void] $coreSet.Add($table.name) }
    }
    # Tagged SecurityInsights but not listed as Sentinel tables by the metadata API
    foreach ($name in 'HuntingBookmarks', 'LLMActivity') { [void] $coreSet.Remove($name) }
}
Write-Verbose "Core Sentinel tables: $($coreSet.Count)"

# Scope signal 2 (Ingested): tables with data in the last 90 days
$ingestedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
if (-not $SkipIngestedTables) {
    $query    = @{ query = 'Usage | where TimeGenerated > ago(90d) | distinct DataType' } | ConvertTo-Json -Compress
    $response = Invoke-ArmRequest -Method POST -Path "$workspacePath/api/query?api-version=2020-08-01" -Payload $query
    $rows     = $null
    if ($response.StatusCode -eq 200) {
        try { $rows = (@(Get-PropertyValue -InputObject ($response.Content | ConvertFrom-Json) -Name 'Tables')[0]).Rows }
        catch { Write-Verbose "Could not parse Usage query response: $($_.Exception.Message)" }
    }
    if ($null -eq $rows) {
        Write-Warning "Could not query the Usage table ($($response.StatusCode)). Tables are selected without the 'Ingested' signal."
    }
    else {
        foreach ($row in $rows) { [void] $ingestedSet.Add([string] @($row)[0]) }
        [void] $ingestedSet.Add('Usage')    # Usage never appears in its own data
    }
    Write-Verbose "Tables with data in the last 90 days: $($ingestedSet.Count)"
}

$payload = @{
    properties = @{
        retentionInDays      = $AnalyticsRetentionInDays
        totalRetentionInDays = $TotalRetentionInDays
    }
} | ConvertTo-Json -Compress

# Phase 1: classify every table
$results = [System.Collections.Generic.List[object]]::new()
$pending = [System.Collections.Generic.List[object]]::new()

foreach ($table in $tables) {
    $name         = $table.name
    $props        = Get-PropertyValue -InputObject $table -Name 'properties'
    $plan         = Get-PropertyValue -InputObject $props -Name 'plan'
    $currentRet   = Get-PropertyValue -InputObject $props -Name 'retentionInDays'
    $currentTotal = Get-PropertyValue -InputObject $props -Name 'totalRetentionInDays'
    $tableType    = Get-PropertyValue -InputObject (Get-PropertyValue -InputObject $props -Name 'schema') -Name 'tableType'
    $source       = $null
    $status       = 'Pending'
    $reason       = $null

    if ($coreSet.Contains($name)) { $source = 'Core' }
    elseif ($tableType -eq 'CustomLog') { $source = 'Custom' }
    elseif ($ingestedSet.Contains($name)) { $source = 'Ingested' }
    elseif ($IncludeTable -and (Test-NameMatch -Name $name -Pattern $IncludeTable)) { $source = 'Include' }

    if (-not $source) {
        $reason = 'Not a Sentinel table (not in Sentinel table groups, custom or ingested)'
    }
    elseif ($plan -ne 'Analytics') {
        $reason = "Plan is '$plan'"
    }
    elseif ($name -match '_(SRCH|RST)$') {
        $reason = 'Search job / restore table'
    }
    elseif (Test-NameMatch -Name $name -Pattern $XdrOnlyTables) {
        $reason = 'XDR-only table'
    }
    elseif (Test-NameMatch -Name $name -Pattern $NotIngestedTables) {
        $reason = 'Not ingested into Sentinel'
    }
    elseif (Test-NameMatch -Name $name -Pattern $DataLakeCandidateTables) {
        $reason = 'Data lake candidate (set Data lake tier in Defender portal)'
    }
    elseif ($ExcludeTable -and (Test-NameMatch -Name $name -Pattern $ExcludeTable)) {
        $reason = 'Excluded by -ExcludeTable'
    }
    elseif ($currentRet -eq $AnalyticsRetentionInDays -and $currentTotal -eq $TotalRetentionInDays) {
        $status = 'AlreadyCompliant'
    }
    elseif (-not $AllowDecrease -and (($currentRet -gt $AnalyticsRetentionInDays) -or ($currentTotal -gt $TotalRetentionInDays))) {
        $reason = 'Would shorten existing retention (use -AllowDecrease)'
    }

    if ($reason) { $status = 'Skipped' }

    $item = [pscustomobject] @{
        Table             = $name
        Source            = $source
        Status            = $status
        Reason            = $reason
        PreviousAnalytics = $currentRet
        PreviousTotal     = $currentTotal
    }
    $results.Add($item)
    if ($status -eq 'Pending') { $pending.Add($item) }
}

# Phase 2: ask once, then patch
if ($pending.Count -gt 0) {
    Write-Host "Planned changes in '$WorkspaceName':"
    $pending |
        Select-Object -Property @(
            'Table'
            'Source'
            @{ Name = 'CurrentAnalytics'; Expression = { $_.PreviousAnalytics } }
            @{ Name = 'CurrentTotal'; Expression = { $_.PreviousTotal } }
            @{ Name = 'NewAnalytics'; Expression = { $AnalyticsRetentionInDays } }
            @{ Name = 'NewTotal'; Expression = { $TotalRetentionInDays } }
        ) |
        Format-Table -AutoSize |
        Out-String |
        Write-Host -NoNewline

    $target = "$($pending.Count) tables in workspace '$WorkspaceName'"
    if ($PSCmdlet.ShouldProcess($target, "Set retention to $AnalyticsRetentionInDays/$TotalRetentionInDays days")) {
        foreach ($item in $pending) {
            $response = Invoke-ArmRequest -Method PATCH -Path "$basePath/$($item.Table)?api-version=$ApiVersion" -Payload $payload
            if ($response.StatusCode -eq 200) {
                $item.Status = 'Updated'
            }
            elseif ($response.StatusCode -eq 202) {
                $item.Status = 'Accepted'
            }
            else {
                $item.Status = 'Failed'
                $item.Reason = "HTTP $($response.StatusCode): $(Get-ErrorMessage -Content $response.Content)"
                Write-Warning "$($item.Table) failed. $($item.Reason)"
            }
        }
    }
    else {
        $declined = if ($WhatIfPreference) { 'WhatIf' } else { 'Declined' }
        foreach ($item in $pending) { $item.Status = $declined }
    }
}

Write-Host "Summary for '$WorkspaceName':"
$results |
    Group-Object -Property Status |
    Sort-Object -Property Name |
    Select-Object -Property @(
        @{ Name = 'Status'; Expression = { $_.Name } }
        @{ Name = 'Tables'; Expression = { $_.Count } }
    ) |
    Format-Table -AutoSize |
    Out-String |
    Write-Host -NoNewline

if ($PassThru) {
    $results
}
