#Requires -Modules Microsoft.Graph.Authentication, Microsoft.Graph.Applications, Microsoft.Graph.Identity.SignIns

<#
.SYNOPSIS
    Creates an Entra app registration for MCP Security Platform M365 integration.

.DESCRIPTION
    Provisions a service principal with Microsoft Graph application permissions
    covering Mail, Calendar, Contacts, Files, SharePoint, and Teams.
    Uses client_credentials flow — no redirect URI, no browser login required.

    After running, copy the printed .env.lab snippet into .env.lab and run:
        make -f Makefile.lab lab-entra-check

.PARAMETER TenantId
    Azure AD tenant ID (required).

.PARAMETER AppName
    Display name for the app registration. Default: mcp-security-lab.

.PARAMETER SecretExpiryYears
    Client secret validity in years. Default: 1.

.PARAMETER Scopes
    Comma-separated list of Graph application permission names to request.
    Default covers Mail, Calendar, Contacts, Files, SharePoint, Teams, and Users.

.PARAMETER OutputEnvFile
    Path to .env.lab file. Auto-discovered by walking up from the script location.
    Override if your .env.lab is elsewhere.

.EXAMPLE
    .\New-M365AppRegistration.ps1 -TenantId "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

.EXAMPLE
    .\New-M365AppRegistration.ps1 -TenantId "..." -AppName "mcp-lab-dev" -SecretExpiryYears 2
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[0-9a-fA-F-]{36}$')]
    [string] $TenantId,

    [string] $AppName = "mcp-security-lab",

    [ValidateRange(1, 3)]
    [int] $SecretExpiryYears = 1,

    [string] $Scopes = "Mail.Read,Mail.ReadWrite,Mail.Send,Calendars.Read,Calendars.ReadWrite,Contacts.Read,User.Read.All,Files.Read.All,Sites.Read.All,Team.ReadBasic.All,ChannelMessage.Read.All",

    [string] $OutputEnvFile = ""
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Auto-discover .env.lab by walking up from the script's directory
if (-not $OutputEnvFile) {
    $search = $PSScriptRoot
    for ($i = 0; $i -lt 5; $i++) {
        $candidate = Join-Path $search ".env.lab"
        if (Test-Path $candidate) { $OutputEnvFile = $candidate; break }
        $search = Split-Path $search -Parent
        if (-not $search) { break }
    }
    if (-not $OutputEnvFile) {
        $OutputEnvFile = Join-Path (Split-Path $PSScriptRoot -Parent | Split-Path -Parent) ".env.lab"
    }
}

# ─── Helpers ──────────────────────────────────────────────────────────────────

function Write-Step([string]$msg) {
    Write-Host "`n── $msg" -ForegroundColor Cyan
}

function Write-OK([string]$msg) {
    Write-Host "   ✓ $msg" -ForegroundColor Green
}

function Write-Warn([string]$msg) {
    Write-Host "   ⚠ $msg" -ForegroundColor Yellow
}

function Write-Fail([string]$msg) {
    Write-Host "   ✗ $msg" -ForegroundColor Red
}

$GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"   # Microsoft Graph (all tenants)

# ─── Step 0: Prerequisites ────────────────────────────────────────────────────

Write-Step "Checking prerequisites"

$requiredModules = @(
    "Microsoft.Graph.Authentication",
    "Microsoft.Graph.Applications",
    "Microsoft.Graph.Identity.SignIns"
)

foreach ($mod in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $mod)) {
        Write-Warn "$mod not found — installing..."
        Install-Module $mod -Scope CurrentUser -Force -AllowClobber
    }
    Import-Module $mod -Force
    Write-OK "$mod loaded"
}

# ─── Step 1: Connect ──────────────────────────────────────────────────────────

Write-Step "Connecting to Entra tenant $TenantId"

$ctx = Get-MgContext
$alreadyConnected = $ctx -and $ctx.TenantId -eq $TenantId -and $ctx.AuthType

if ($alreadyConnected) {
    $accountDisplay = $ctx.PSObject.Properties['Account'].Value
    if (-not $accountDisplay) { $accountDisplay = $ctx.ClientId }
    Write-OK "Already authenticated — skipping device login"
    Write-OK "Authenticated as: $accountDisplay"
    Write-OK "Tenant:           $($ctx.TenantId)"
} else {
    Connect-MgGraph `
        -TenantId $TenantId `
        -Scopes "Application.ReadWrite.All","AppRoleAssignment.ReadWrite.All","Directory.ReadWrite.All" `
        -UseDeviceCode `
        -ContextScope Process

    $ctx = Get-MgContext
    $accountDisplay = $ctx.PSObject.Properties['Account'].Value
    if (-not $accountDisplay) { $accountDisplay = $ctx.ClientId }
    Write-OK "Authenticated as: $accountDisplay"
    Write-OK "Tenant:           $($ctx.TenantId)"
}

# ─── Step 2: Resolve requested permissions from live Graph service principal ──
# Look up AppRole IDs directly from the Graph SP — no hardcoded UUIDs.

Write-Step "Resolving permissions from Microsoft Graph service principal"

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GRAPH_APP_ID'"
$graphAppRoles = @{}
foreach ($role in $graphSp.AppRoles) {
    $graphAppRoles[$role.Value] = $role.Id
}

$requestedScopes = $Scopes -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
$resolvedPermissions = [System.Collections.Generic.List[hashtable]]::new()
$unknownPerms = [System.Collections.Generic.List[string]]::new()

foreach ($scope in $requestedScopes) {
    if ($graphAppRoles.ContainsKey($scope)) {
        $resolvedPermissions.Add(@{ Id = $graphAppRoles[$scope]; Type = "Role" })
        Write-OK "$scope → $($graphAppRoles[$scope])"
    } else {
        $unknownPerms.Add($scope)
        Write-Warn "$scope — not found in Graph AppRoles (may be delegated-only), skipping"
    }
}

if ($resolvedPermissions.Count -eq 0) {
    throw "No valid application permissions resolved. Check the -Scopes parameter."
}

# ─── Step 3: Check for existing app ──────────────────────────────────────────

Write-Step "Checking for existing app registration '$AppName'"

$existingApp = Get-MgApplication -Filter "displayName eq '$AppName'" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if ($existingApp) {
    Write-Warn "App '$AppName' already exists (Id: $($existingApp.Id), AppId: $($existingApp.AppId))"
    $choice = Read-Host "   Update existing app? [y/N]"
    if ($choice -notmatch "^[yY]$") {
        Write-Host "Aborted." -ForegroundColor Yellow
        exit 0
    }
    $app = $existingApp
    $updating = $true
} else {
    $updating = $false
}

# ─── Step 4: Create or update app registration ───────────────────────────────

Write-Step "$(if ($updating) { 'Updating' } else { 'Creating' }) app registration"

# SDK v2.x requires plain hashtables — typed [MicrosoftGraphResourceAccess] casts
# are v1.x only and throw "Object reference not set" on v2.x at runtime.
$appParams = @{
    DisplayName    = $AppName
    SignInAudience = "AzureADMyOrg"
    RequiredResourceAccess = @(
        @{
            ResourceAppId  = $GRAPH_APP_ID
            ResourceAccess = @(
                $resolvedPermissions | ForEach-Object { @{ Id = $_.Id; Type = $_.Type } }
            )
        }
    )
}

if ($updating) {
    Update-MgApplication -ApplicationId $app.Id @appParams
    $app = Get-MgApplication -ApplicationId $app.Id
    Write-OK "App registration updated"
} else {
    $app = New-MgApplication @appParams
    if (-not $app -or -not $app.Id) {
        throw "New-MgApplication returned no object. Check Graph permissions and re-authenticate."
    }
    Write-OK "App registration created"
}

Write-OK "Application Id:  $($app.Id)"
Write-OK "Application (client) Id: $($app.AppId)"

# ─── Step 5: Create or reuse service principal ───────────────────────────────

Write-Step "Creating service principal"

$sp = Get-MgServicePrincipal -Filter "appId eq '$($app.AppId)'" -ErrorAction SilentlyContinue |
    Select-Object -First 1

if (-not $sp) {
    $sp = New-MgServicePrincipal -AppId $app.AppId
    Write-OK "Service principal created"
} else {
    Write-OK "Service principal already exists"
}

Write-OK "SP Object Id: $($sp.Id)"

# ─── Step 6: Create client secret ────────────────────────────────────────────

Write-Step "Creating client secret (expiry: $SecretExpiryYears year(s))"

$expiryDate = (Get-Date).AddYears($SecretExpiryYears).ToUniversalTime().ToString("o")

$secretParams = @{
    PasswordCredential = @{
        DisplayName = "$AppName-secret-$(Get-Date -Format 'yyyyMMdd')"
        EndDateTime = $expiryDate
    }
}

$secretResult = Add-MgApplicationPassword -ApplicationId $app.Id @secretParams

Write-OK "Secret created (KeyId: $($secretResult.KeyId))"
Write-Warn "Client secret shown ONCE — copy it now"

$clientSecret = $secretResult.SecretText

# ─── Step 7: Grant admin consent (app role assignments) ──────────────────────

Write-Step "Granting admin consent for application permissions"

$graphSp = Get-MgServicePrincipal -Filter "appId eq '$GRAPH_APP_ID'"

foreach ($perm in $resolvedPermissions) {
    $permId = $perm.Id

    $existing = Get-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $sp.Id |
        Where-Object { $_.AppRoleId -eq $permId } |
        Select-Object -First 1

    if ($existing) {
        Write-OK "Already consented: $permId"
        continue
    }

    try {
        New-MgServicePrincipalAppRoleAssignment `
            -ServicePrincipalId $sp.Id `
            -PrincipalId        $sp.Id `
            -ResourceId         $graphSp.Id `
            -AppRoleId          $permId | Out-Null
        Write-OK "Consented: $permId"
    } catch {
        Write-Warn "Failed to consent $permId — $($_.Exception.Message)"
    }
}

# ─── Step 8: Verify — acquire token ──────────────────────────────────────────

Write-Step "Verifying — acquiring client_credentials token"

Start-Sleep -Seconds 5   # brief pause for consent to propagate

try {
    $tokenResponse = Invoke-RestMethod `
        -Method Post `
        -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" `
        -ContentType "application/x-www-form-urlencoded" `
        -Body @{
            grant_type    = "client_credentials"
            client_id     = $app.AppId
            client_secret = $clientSecret
            scope         = "https://graph.microsoft.com/.default"
        }

    $accessToken = $tokenResponse.access_token
    Write-OK "Token acquired (expires_in: $($tokenResponse.expires_in)s)"
} catch {
    Write-Fail "Token acquisition failed: $($_.Exception.Message)"
    Write-Warn "Admin consent may still be propagating — retry in 30s with lab-entra-check"
    $accessToken = $null
}

# ─── Step 9: Verify — call Graph API ─────────────────────────────────────────

if ($accessToken) {
    Write-Step "Verifying — GET /v1.0/organization"
    try {
        $org = Invoke-RestMethod `
            -Uri "https://graph.microsoft.com/v1.0/organization" `
            -Headers @{ Authorization = "Bearer $accessToken" }
        Write-OK "Graph API reachable — tenant: $($org.value[0].displayName)"
    } catch {
        Write-Warn "Graph API call failed: $($_.Exception.Message)"
    }
}

# ─── Step 10: Output .env.lab snippet ────────────────────────────────────────

$envSnippet = @"

# ── Entra / M365 (generated by New-M365AppRegistration.ps1 on $(Get-Date -Format 'yyyy-MM-dd')) ──
ENTRA_TENANT_ID=$TenantId
ENTRA_CLIENT_ID=$($app.AppId)
ENTRA_CLIENT_SECRET=$clientSecret
"@

Write-Host ""
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta
Write-Host $envSnippet -ForegroundColor White
Write-Host "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" -ForegroundColor Magenta
Write-Host ""

# Remove any stale ENTRA_* lines from .env.lab, then append fresh values
if (Test-Path $OutputEnvFile) {
    $existing = Get-Content $OutputEnvFile | Where-Object { $_ -notmatch '^ENTRA_(TENANT_ID|CLIENT_ID|CLIENT_SECRET)=' }
    Set-Content -Path $OutputEnvFile -Value $existing
    Write-OK "Removed stale ENTRA_* lines from $OutputEnvFile"
}
Add-Content -Path $OutputEnvFile -Value $envSnippet
Write-OK "Written to $OutputEnvFile"

# ─── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host "Done." -ForegroundColor Green
Write-Host ""
Write-Host "App registration summary:" -ForegroundColor Cyan
Write-Host "  Display name  : $AppName"
Write-Host "  Tenant Id     : $TenantId"
Write-Host "  Client Id     : $($app.AppId)"
Write-Host "  Object Id     : $($app.Id)"
Write-Host "  SP Object Id  : $($sp.Id)"
Write-Host "  Secret expiry : $expiryDate"
Write-Host "  Permissions   : $($resolvedPermissions.Count) Graph application roles granted"
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Copy the .env.lab snippet above into .env.lab"
Write-Host "  2. make -f Makefile.lab lab-entra-check"
Write-Host ""

if ($unknownPerms.Count -gt 0) {
    Write-Warn "The following requested scopes were not recognised and were skipped:"
    $unknownPerms | ForEach-Object { Write-Warn "  - $_" }
    Write-Warn "Add them to `$GraphPermissionIds in this script if needed."
}
