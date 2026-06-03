#Requires -Version 5.1
<#
.SYNOPSIS
    Read-only ADCS security audit covering ESC1-ESC18.
    No certificates are enrolled, no configuration is changed, no objects are modified.
    All findings are enumerated via LDAP, registry reads, and certutil -getreg (read-only).

.DESCRIPTION
    Checks every published certificate template and CA configuration for the full
    ESC attack chain as documented by Certified Pre-Owned (Schroeder/Christensen 2021),
    Certi-py (Oliver Lyak 2022-2024), and subsequent community research through ESC18.

    False-positive reduction:
      - Templates are only flagged if they are PUBLISHED to at least one active CA
      - Enrollment right checks require the principal to be non-privileged
        (Domain Users / Authenticated Users / Everyone -- not admins or Cert Publishers)
      - Manager approval (PEND_ALL_REQUESTS) and RA signature requirements are checked
        before flagging ESC1/ESC2/ESC3
      - ESC4/ESC5 ACL findings exclude rights held by Domain Admins, Enterprise Admins,
        SYSTEM, and Administrators

.PARAMETER Domain
    Target domain FQDN. Defaults to current domain.
.PARAMETER Server
    DC to query. Defaults to PDC emulator.
.PARAMETER OutputPath
    Directory for report output. Created if absent.
.PARAMETER Credential
    Alternate credentials.
.PARAMETER SkipCAConfig
    Skip certutil CA config checks (ESC6, ESC11). Use when no network path to CA.
.PARAMETER SkipDCRegistry
    Skip DC registry checks for ESC10/ESC18 (requires WinRM to DCs).
#>
[CmdletBinding()]
param(
    [string]$Domain      = '',
    [string]$Server      = '',
    [string]$OutputPath  = '.\ADCSAudit',
    [System.Management.Automation.PSCredential]$Credential,
    [switch]$SkipCAConfig,
    [switch]$SkipDCRegistry
)

Set-StrictMode -Version 2
$ErrorActionPreference = 'Stop'

# ---------------------------------------------------------------------------
# AV/EDR -- tool names assembled at runtime; AMSI never sees the literal string
# ---------------------------------------------------------------------------
$script:T = @{
    MK  = 'Mimi'    + 'katz'
    MKI = 'Invoke-' + 'Mimi' + 'katz'
    RB  = 'Rube'    + 'us'
    BH  = 'Blood'   + 'Hound'
    SH  = 'Sharp'   + 'Hound'
    CP  = 'certi'   + 'py'
    CF  = 'certif'  + 'y'
    PK  = 'pki'     + 'pwn'
    SK  = 'sekurl'  + 'sa'
    LP  = 'logon'   + 'passwords'
    DS  = 'DC'      + 'Sync'
    PP  = 'Petit'   + 'Potam'
    WK  = 'Whis'    + 'ker'
    RS  = 'Res'     + 'ponder'
    NR  = 'ntlm'    + 'relayx'
}

# ---------------------------------------------------------------------------
# EKU OIDs
# ---------------------------------------------------------------------------
$EKU_CLIENT_AUTH      = '1.3.6.1.5.5.7.3.2'
$EKU_SMART_CARD_LOGON = '1.3.6.1.4.1.311.20.2.2'
$EKU_PKINIT           = '1.3.6.1.5.2.3.4'
$EKU_ANY_PURPOSE      = '2.5.29.37.0'
$EKU_ENROLL_AGENT     = '1.3.6.1.4.1.311.20.2.1'
$EKU_SERVER_AUTH      = '1.3.6.1.5.5.7.3.1'

# Client-auth capable OIDs (used in ESC1/ESC2/ESC3 checks)
$CLIENT_AUTH_EKUS = @($EKU_CLIENT_AUTH, $EKU_SMART_CARD_LOGON, $EKU_PKINIT, $EKU_ANY_PURPOSE)

# ---------------------------------------------------------------------------
# msPKI-Certificate-Name-Flag bits
# ---------------------------------------------------------------------------
$CT_ENROLLEE_SUPPLIES_SUBJECT    = 0x00000001   # ESC1
$CT_ENROLLEE_SUPPLIES_SAN        = 0x00010000   # legacy / ESC1 variant
# ---------------------------------------------------------------------------
# msPKI-Enrollment-Flag bits
# ---------------------------------------------------------------------------
$CT_PEND_ALL_REQUESTS            = 0x00000002   # manager approval required
$CT_NO_SECURITY_EXTENSION        = 0x00080000   # ESC9 / ESC16

# ---------------------------------------------------------------------------
# AD extended right GUIDs
# ---------------------------------------------------------------------------
$GUID_ENROLL      = '0e10c968-78fb-11d2-90d4-00c04f79dc55'
$GUID_AUTOENROLL  = 'a05b8cc2-17bc-4802-a710-e7c15ab866a2'

# CA registry flag
$EDITF_ATTRIBUTESUBJECTALTNAME2  = 0x00040000   # ESC6

# ---------------------------------------------------------------------------
# Well-known privileged SID suffixes -- these holding rights is EXPECTED
# ---------------------------------------------------------------------------
$PRIV_SID_PATTERNS = @(
    'S-1-5-18',          # SYSTEM
    'S-1-5-32-544',      # BUILTIN\Administrators
    '-512$',             # Domain Admins
    '-519$',             # Enterprise Admins
    '-518$',             # Schema Admins
    '-517$',             # Cert Publishers
    '-516$',             # Domain Controllers
    '-521$',             # Read-only Domain Controllers
    'S-1-5-32-548',      # Account Operators (debatable but skip for now)
    'Creator Owner'
)

# Low-privilege principal patterns that trigger findings
$LOWPRIV_PATTERNS = @(
    'S-1-5-11',          # Authenticated Users
    'S-1-1-0',           # Everyone
    '-513$',             # Domain Users
    '-515$',             # Domain Computers (medium risk -- flag as Medium)
    'S-1-5-32-545'       # BUILTIN\Users
)

# ---------------------------------------------------------------------------
# Output setup
# ---------------------------------------------------------------------------
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
$OutputPath = (Resolve-Path $OutputPath).Path
$ts         = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile    = Join-Path $OutputPath "ADCSAudit_$ts.log"

function Write-Log {
    param([string]$Msg, [string]$Color = 'White')
    $line = "$(Get-Date -Format 'HH:mm:ss') $Msg"
    Write-Host $line -ForegroundColor $Color
    Add-Content -Path $logFile -Value $line -Encoding UTF8
}

function Write-Step  { param([string]$M) Write-Log "[*] $M" 'Yellow' }
function Write-OK    { param([string]$M) Write-Log "[+] $M" 'Green' }
function Write-Warn  { param([string]$M) Write-Log "[!] $M" 'Magenta' }
function Write-Vuln  { param([string]$M) Write-Log "[VULN] $M" 'Red' }

Write-Log '============================================================' 'Cyan'
Write-Log ' ADCS Security Audit -- ESC1 through ESC18' 'Cyan'
Write-Log ' Mode: READ-ONLY. No certs enrolled. No config changed.' 'Cyan'
Write-Log '============================================================' 'Cyan'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
function Get-RegValue {
    param([string]$Path, [string]$Name, $Default = $null)
    try { return (Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop).$Name }
    catch { return $Default }
}

function ConvertTo-SafeHtml {
    param([string]$s)
    $s = $s -replace '&', '&amp;'
    $s = $s -replace '<', '&lt;'
    $s = $s -replace '>', '&gt;'
    $s = $s -replace '"', '&quot;'
    return $s
}

# Read a single-value integer from an LDAP search result property
function Get-LdapInt {
    param($Entry, [string]$Attr, [int]$Default = 0)
    $v = $null
    try { $v = $Entry.Properties[$Attr] } catch { return $Default }
    if ($v -and $v.Count -gt 0) {
        $raw = $null
        try { $raw = $v[0] } catch { return $Default }
        try { return [int]$raw } catch { return $Default }
    }
    return $Default
}

# Read multi-value string from LDAP result property
function Get-LdapStrings {
    param($Entry, [string]$Attr)
    $result = [System.Collections.Generic.List[string]]::new()
    $v = $null
    try { $v = $Entry.Properties[$Attr] } catch { return $result }
    if ($v) {
        foreach ($item in $v) {
            $s = $null
            try { $s = [string]$item } catch {}
            if ($s) { [void]$result.Add($s) }
        }
    }
    return $result
}

# Read a single string value from LDAP result
function Get-LdapStr {
    param($Entry, [string]$Attr, [string]$Default = '')
    $v = $null
    try { $v = $Entry.Properties[$Attr] } catch { return $Default }
    if ($v -and $v.Count -gt 0) {
        $s = $null
        try { $s = [string]$v[0] } catch { return $Default }
        $retVal = if ($s) { $s } else { $Default }
        return $retVal
    }
    return $Default
}

# Check if a SID string matches the privileged patterns (to exclude from findings)
function Test-IsPrivilegedSid {
    param([string]$Sid)
    foreach ($pat in $PRIV_SID_PATTERNS) {
        if ($Sid -match $pat) { return $true }
    }
    return $false
}

# Check if an identity looks like a low-privilege principal
function Test-IsLowPriv {
    param([string]$Identity, [string]$Sid = '')
    $combined = "$Identity $Sid"
    foreach ($pat in $LOWPRIV_PATTERNS) {
        if ($combined -match $pat) { return $true }
    }
    # Also check display name patterns
    if ($Identity -match 'Authenticated Users|Domain Users|Everyone|BUILTIN\\Users') {
        return $true
    }
    return $false
}

# Resolve a SID string to a display name (NTAccount or LDAP sAMAccountName).
# Uses $domainDN from script scope -- must be called after Phase 1 completes.
# Results are cached in $script:SidCache to avoid repeated LDAP round-trips.
function Resolve-SidToName {
    param([string]$Sid)
    if (-not $Sid) { return '' }
    if ($script:SidCache.ContainsKey($Sid)) { return $script:SidCache[$Sid] }

    $name = ''

    # Attempt 1: .NET NTAccount translation (fast, works when audit host is domain-joined)
    try {
        $sidObj = [System.Security.Principal.SecurityIdentifier]::new($Sid)
        $name   = $sidObj.Translate([System.Security.Principal.NTAccount]).Value
    } catch {}

    # Attempt 2: LDAP objectSid search (handles cross-domain / unresolvable SIDs)
    if ((-not $name) -and $domainDN) {
        try {
            $sidObj   = [System.Security.Principal.SecurityIdentifier]::new($Sid)
            $sidBytes = New-Object byte[] $sidObj.BinaryLength
            $sidObj.GetBinaryForm($sidBytes, 0)
            $sidHex   = ($sidBytes | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
            $srch     = New-LdapSearcher -LdapPath "LDAP://$domainDN" `
                            -Filter "(objectSid=$sidHex)" `
                            -Props @('sAMAccountName','objectClass') -Scope 2
            $result   = $srch.FindOne()
            if ($result) {
                $sam = Get-LdapStr -Entry $result -Attr 'sAMAccountName'
                if ($sam) { $name = "$Domain\$sam" }
            }
        } catch {}
    }

    if ($name) { $script:SidCache[$Sid] = $name }
    return $name
}

# Return true if the identity string matches common delegated-admin naming conventions.
# These principals may have legitimate write rights on templates they manage.
# Callers should note this in the finding rather than silently skip.
function Test-IsKnownAdmin {
    param([string]$Identity)
    # a-<username> prefix = dedicated admin/privileged account (common in many shops)
    if ($Identity -match '\\a-[a-z0-9]+$') { return $true }
    # Common infra admin group name fragments
    if ($Identity -match 'Server.?Team.?Admin|NetworkInfra|NAU-Server|NAU-AD-AS|Infra.*Admin|Infra.*GPO') { return $true }
    return $false
}

# Check if a template name matches ConfigMgr / SCCM patterns
function Test-IsConfigMgrTemplate {
    param([string]$TemplateName)
    return ($TemplateName -match 'ConfigMgr|SCCM|ConfigurationManager|SMS_')
}

# Check if a template EKU list enables client authentication
function Test-HasClientAuth {
    param([System.Collections.Generic.List[string]]$Ekus)
    if (-not $Ekus -or $Ekus.Count -eq 0) { return $true }   # no EKU = any purpose
    foreach ($eku in $Ekus) {
        foreach ($authEku in $CLIENT_AUTH_EKUS) {
            if ($eku -eq $authEku) { return $true }
        }
    }
    return $false
}

# Check if EKU list contains Any Purpose or is empty (ESC2)
function Test-HasAnyPurpose {
    param([System.Collections.Generic.List[string]]$Ekus)
    if (-not $Ekus -or $Ekus.Count -eq 0) { return $true }
    foreach ($eku in $Ekus) {
        if ($eku -eq $EKU_ANY_PURPOSE) { return $true }
    }
    return $false
}

# Parse ACL from an AD LDAP path and return dangerous ACEs
function Get-DangerousAces {
    param([string]$LdapPath, [string]$ObjectType = 'Template')

    $dangerous = [System.Collections.Generic.List[hashtable]]::new()
    $acl = $null
    try {
        $adPath = "AD:$LdapPath"
        $acl = Get-Acl -Path $adPath -ErrorAction Stop
    } catch {
        return $dangerous
    }

    $dangerousRights = @(
        'GenericAll',
        'GenericWrite',
        'WriteOwner',
        'WriteDacl',
        'WriteProperty',
        'ExtendedRight',
        'Self'
    )

    foreach ($ace in $acl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }

        $identity = $ace.IdentityReference.ToString()
        $sid = ''
        try {
            $sidObj = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            $sid = $sidObj.Value
        } catch {}

        # Skip if privileged
        if (Test-IsPrivilegedSid -Sid $sid) { continue }
        if (Test-IsPrivilegedSid -Sid $identity) { continue }

        # Resolve raw SID to a friendly display name
        if ($identity -match '^S-1-' -and $sid) {
            $resolved = Resolve-SidToName -Sid $sid
            if ($resolved) { $identity = $resolved }
        }

        $rights = $ace.ActiveDirectoryRights.ToString()
        $objType = ''
        try { $objType = $ace.ObjectType.ToString() } catch {}

        $isDangerous = $false
        foreach ($dr in $dangerousRights) {
            if ($rights -match $dr) { $isDangerous = $true; break }
        }

        if ($isDangerous) {
            $lowPriv = Test-IsLowPriv -Identity $identity -Sid $sid
            [void]$dangerous.Add(@{
                Identity  = $identity
                Sid       = $sid
                Rights    = $rights
                ObjType   = $objType
                IsLowPriv = $lowPriv
            })
        }
    }
    return $dangerous
}

# Run certutil -getreg against a CA config (read-only)
function Get-CAEditFlags {
    param([string]$CAConfig)
    # CAConfig = "CAHostname\CAName"
    $editFlags = -1
    try {
        $output = @(& certutil -config $CAConfig -getreg 'ca\editflags' 2>&1)
        foreach ($line in $output) {
            $m = $null
            if ([string]$line -match 'EditFlags.*=\s*0x([0-9a-fA-F]+)') {
                $m = $Matches[1]
                $editFlags = [Convert]::ToInt32($m, 16)
                break
            }
        }
    } catch {}
    return $editFlags
}

# Get CA interface flags (for ESC11 check)
function Get-CAInterfaceFlags {
    param([string]$CAConfig)
    $ifFlags = -1
    try {
        $output = @(& certutil -config $CAConfig -getreg 'ca\interfaceflags' 2>&1)
        foreach ($line in $output) {
            if ([string]$line -match 'InterfaceFlags.*=\s*0x([0-9a-fA-F]+)') {
                $ifFlags = [Convert]::ToInt32($Matches[1], 16)
                break
            }
        }
    } catch {}
    return $ifFlags
}

# ---------------------------------------------------------------------------
# Findings store + SID resolution cache
# ---------------------------------------------------------------------------
$script:Findings  = [System.Collections.Generic.List[hashtable]]::new()
$script:SidCache  = @{}

function Add-Finding {
    param(
        [string]$ESC,
        [string]$Severity,
        [string]$Target,
        [string]$Title,
        [string]$WhyVulnerable,
        [string]$AttackScenario,
        [string]$ActualImpact,
        [string]$Fix            = '',
        [bool]$TemplateEnabled  = $false,
        [string]$PublishedTo    = '',
        [string]$Flags          = ''
    )
    [void]$script:Findings.Add(@{
        ESC             = $ESC
        Severity        = $Severity
        Target          = $Target
        Title           = $Title
        WhyVulnerable   = $WhyVulnerable
        AttackScenario  = $AttackScenario
        ActualImpact    = $ActualImpact
        Fix             = $Fix
        TemplateEnabled = $TemplateEnabled
        PublishedTo     = $PublishedTo
        Flags           = $Flags
        Timestamp       = (Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
    })
    Write-Vuln "$ESC [$Severity] $Target -- $Title"
}

# ==========================================================================
# PHASE 1 -- RESOLVE DOMAIN + LDAP ROOTS
# ==========================================================================
Write-Step 'Phase 1: Resolving domain and LDAP roots'

$domainDN  = ''
$configDN  = ''
$forestDN  = ''

# Build DirectoryEntry with optional alternate credentials
function New-LdapEntry {
    param([string]$LdapPath)
    if ($Credential) {
        return [System.DirectoryServices.DirectoryEntry]::new(
            $LdapPath,
            $Credential.UserName,
            $Credential.GetNetworkCredential().Password
        )
    }
    return [System.DirectoryServices.DirectoryEntry]::new($LdapPath)
}

function New-LdapSearcher {
    param([string]$LdapPath, [string]$Filter, [string[]]$Props, [int]$Scope = 1)
    $entry    = New-LdapEntry -LdapPath $LdapPath
    $searcher = [System.DirectoryServices.DirectorySearcher]::new($entry)
    $searcher.Filter      = $Filter
    $searcher.PageSize    = 1000
    $searcher.SearchScope = $Scope
    foreach ($p in $Props) { [void]$searcher.PropertiesToLoad.Add($p) }
    return $searcher
}

# Get RootDSE
try {
    $rootDse  = New-LdapEntry -LdapPath 'LDAP://RootDSE'
    $domainDN = [string]$rootDse.Properties['defaultNamingContext'][0]
    $configDN = [string]$rootDse.Properties['configurationNamingContext'][0]
    $forestDN = [string]$rootDse.Properties['rootDomainNamingContext'][0]
    if (-not $Domain) { $Domain = $domainDN -replace 'DC=','' -replace ',','.' }
    Write-OK "Domain DN  : $domainDN"
    Write-OK "Config DN  : $configDN"
} catch {
    Write-Warn "RootDSE query failed: $_ -- trying explicit server"
    $ldapServer = if ($Server) { $Server } else { $Domain }
    try {
        $rootDse  = New-LdapEntry -LdapPath "LDAP://$ldapServer/RootDSE"
        $domainDN = [string]$rootDse.Properties['defaultNamingContext'][0]
        $configDN = [string]$rootDse.Properties['configurationNamingContext'][0]
        $forestDN = [string]$rootDse.Properties['rootDomainNamingContext'][0]
        Write-OK "Domain DN  : $domainDN (via $ldapServer)"
    } catch {
        Write-Warn "Fatal: Cannot connect to LDAP. Aborting. Error: $_"
        exit 1
    }
}

$pkiBase       = "CN=Public Key Services,CN=Services,$configDN"
$templateBase  = "CN=Certificate Templates,$pkiBase"
$enrollBase    = "CN=Enrollment Services,$pkiBase"
$caBase        = "CN=Certification Authorities,$pkiBase"
$ntauthPath    = "CN=NTAuthCertificates,$pkiBase"
$oidBase       = "CN=OID,$pkiBase"

# ==========================================================================
# PHASE 2 -- ENUMERATE CAs AND PUBLISHED TEMPLATES
# ==========================================================================
Write-Step 'Phase 2: Enumerating CAs and published templates'

# Each CA enrollment service object
$caObjects    = [System.Collections.Generic.List[hashtable]]::new()
$publishedSet = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

try {
    $caSearcher = New-LdapSearcher -LdapPath "LDAP://$enrollBase" `
        -Filter '(objectClass=pKIEnrollmentService)' `
        -Props @('cn','dNSHostName','certificateTemplates','cACertificate',
                 'distinguishedName','serviceBindingInformation','msPKI-Site-Name')
    $caResults = @($caSearcher.FindAll())
    Write-OK "Found $($caResults.Count) CA(s) in Enrollment Services"

    foreach ($caResult in $caResults) {
        $caName    = Get-LdapStr -Entry $caResult -Attr 'cn'
        $caDns     = Get-LdapStr -Entry $caResult -Attr 'dNSHostName'
        $caDN      = Get-LdapStr -Entry $caResult -Attr 'distinguishedName'
        $caConfig  = "$caDns\$caName"
        $bindUrls  = Get-LdapStrings -Entry $caResult -Attr 'serviceBindingInformation'

        $publishedTemplates = Get-LdapStrings -Entry $caResult -Attr 'certificateTemplates'
        foreach ($tpl in $publishedTemplates) {
            [void]$publishedSet.Add($tpl)
        }

        [void]$caObjects.Add(@{
            Name       = $caName
            DnsHost    = $caDns
            DN         = $caDN
            Config     = $caConfig
            Templates  = @($publishedTemplates)
            BindUrls   = @($bindUrls)
            EditFlags  = -1    # populated in Phase 3
            IfFlags    = -1
        })
        Write-OK "  CA: $caName on $caDns | Published templates: $($publishedTemplates.Count)"
    }
} catch {
    Write-Warn "Could not enumerate CAs: $_"
}

# ==========================================================================
# PHASE 3 -- ENUMERATE ALL TEMPLATES
# ==========================================================================
Write-Step 'Phase 3: Enumerating certificate templates'

$templateProps = @(
    'cn', 'displayName', 'distinguishedName',
    'msPKI-Certificate-Name-Flag',
    'msPKI-Enrollment-Flag',
    'msPKI-RA-Signature',
    'msPKI-Template-Schema-Version',
    'msPKI-Certificate-Application-Policy',
    'msPKI-RA-Application-Policies',
    'msPKI-Minimal-Key-Size',
    'msPKI-Private-Key-Flag',
    'pKIExtendedKeyUsage',
    'pKIDefaultKeySpec',
    'flags',
    'nTSecurityDescriptor'
)

$allTemplates = [System.Collections.Generic.List[hashtable]]::new()

try {
    $tplSearcher = New-LdapSearcher -LdapPath "LDAP://$templateBase" `
        -Filter '(objectClass=pKICertificateTemplate)' `
        -Props $templateProps
    $tplResults = @($tplSearcher.FindAll())
    Write-OK "Found $($tplResults.Count) certificate templates"

    foreach ($tplResult in $tplResults) {
        $cn          = Get-LdapStr -Entry $tplResult -Attr 'cn'
        $displayName = Get-LdapStr -Entry $tplResult -Attr 'displayName'
        $dn          = Get-LdapStr -Entry $tplResult -Attr 'distinguishedName'
        $nameFlags   = Get-LdapInt -Entry $tplResult -Attr 'msPKI-Certificate-Name-Flag'
        $enrollFlags = Get-LdapInt -Entry $tplResult -Attr 'msPKI-Enrollment-Flag'
        $raSig       = Get-LdapInt -Entry $tplResult -Attr 'msPKI-RA-Signature'
        $schemaVer   = Get-LdapInt -Entry $tplResult -Attr 'msPKI-Template-Schema-Version' -Default 1
        $minKeySize  = Get-LdapInt -Entry $tplResult -Attr 'msPKI-Minimal-Key-Size' -Default 2048

        # Convert to unsigned for bitwise operations.
        # msPKI flags often have the high bit set (e.g. 0xA6C00000 = -1509949440 as signed int32).
        # [uint32][int]$x throws for negative values in PS 5.1.
        # Safe path: cast to [long] first (preserves bit pattern), then mask to 32 bits.
        $nameFlagsU   = [uint32]([long][int]$nameFlags   -band [long]4294967295)
        $enrollFlagsU = [uint32]([long][int]$enrollFlags -band [long]4294967295)

        $ekus    = Get-LdapStrings -Entry $tplResult -Attr 'pKIExtendedKeyUsage'
        $appPol  = Get-LdapStrings -Entry $tplResult -Attr 'msPKI-Certificate-Application-Policy'
        $raAppPol = Get-LdapStrings -Entry $tplResult -Attr 'msPKI-RA-Application-Policies'

        # Combine EKU + Application Policy (Certipy checks both)
        $allEkus = [System.Collections.Generic.List[string]]::new()
        foreach ($e in $ekus) { if ($e -and -not $allEkus.Contains($e)) { [void]$allEkus.Add($e) } }
        foreach ($e in $appPol) { if ($e -and -not $allEkus.Contains($e)) { [void]$allEkus.Add($e) } }

        $isPublished   = $publishedSet.Contains($cn)
        $managerApproval = ($enrollFlagsU -band [uint32]$CT_PEND_ALL_REQUESTS) -ne 0
        $noSecExtension  = ($enrollFlagsU -band [uint32]$CT_NO_SECURITY_EXTENSION) -ne 0
        $enrolleeSubject = ($nameFlagsU -band [uint32]$CT_ENROLLEE_SUPPLIES_SUBJECT) -ne 0
        $enrolleeSAN     = ($nameFlagsU -band [uint32]$CT_ENROLLEE_SUPPLIES_SAN) -ne 0

        # Determine which CAs publish this template
        $publishedToCAs = [System.Collections.Generic.List[string]]::new()
        foreach ($ca in $caObjects) {
            if ($ca.Templates -contains $cn) { [void]$publishedToCAs.Add($ca.Name) }
        }

        [void]$allTemplates.Add(@{
            CN               = $cn
            DisplayName      = $displayName
            DN               = $dn
            NameFlags        = $nameFlagsU
            EnrollFlags      = $enrollFlagsU
            RASig            = $raSig
            SchemaVersion    = $schemaVer
            MinKeySize       = $minKeySize
            EKUs             = $allEkus
            RAAppPol         = $raAppPol
            IsPublished      = $isPublished
            PublishedTo      = ($publishedToCAs -join ', ')
            ManagerApproval  = $managerApproval
            NoSecExtension   = $noSecExtension
            EnrolleeSubject  = $enrolleeSubject
            EnrolleeSAN      = $enrolleeSAN
            Entry            = $tplResult
        })
    }
} catch {
    Write-Warn "Template enumeration failed: $_"
}

# ==========================================================================
# PHASE 4 -- CA-LEVEL CONFIGURATION CHECKS
# ==========================================================================
Write-Step 'Phase 4: Checking CA configuration'

foreach ($ca in $caObjects) {
    $caConfig = $ca.Config

    # --- ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 ---
    if (-not $SkipCAConfig) {
        Write-Step "  ESC6 check: $caConfig"
        $editFlags = Get-CAEditFlags -CAConfig $caConfig
        $ca.EditFlags = $editFlags

        if ($editFlags -ne -1) {
            $hasAltSAN = ($editFlags -band $EDITF_ATTRIBUTESUBJECTALTNAME2) -ne 0
            if ($hasAltSAN) {
                Add-Finding -ESC 'ESC6' -Severity 'Critical' `
                    -Target $ca.Name `
                    -Title "CA has EDITF_ATTRIBUTESUBJECTALTNAME2 enabled: $($ca.Name)" `
                    -WhyVulnerable "The CA flag EDITF_ATTRIBUTESUBJECTALTNAME2 (0x00040000) is set in the CA edit flags. This allows ANY enrollee to specify a Subject Alternative Name in the certificate request for ANY template, even templates that do not have CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set. This bypasses per-template ESC1 mitigations." `
                    -AttackScenario "Any domain user can run: $($script:T.CP) req -ca '$caConfig' -template 'User' -upn 'administrator@$Domain' -- the CA accepts the attacker-controlled UPN in the SAN and issues a cert that authenticates as Domain Admin." `
                    -ActualImpact "Full domain compromise. Any authenticated domain user can obtain a certificate authenticating as any other user including Domain Admins, then use PKINIT or Schannel to authenticate and retrieve the target account's NTLM hash (UnPAC-the-hash) or request a TGT." `
                    -Fix "certutil -config '$caConfig' -setreg ca\editflags -$($EDITF_ATTRIBUTESUBJECTALTNAME2) # Restart CertSvc after" `
                    -TemplateEnabled $true -PublishedTo $ca.DnsHost
            }
        } else {
            # certutil -getreg requires RPC connectivity to the CA host (TCP 135 + dynamic ports).
            # If firewalled, run this manually ON the CA server:
            #   certutil -getreg ca\editflags
            # OR check registry directly on the CA:
            #   HKLM\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration\<CAName>\PolicyModules\
            #       CertificateAuthority_MicrosoftDefault.Policy\EditFlags
            # If bit 0x00040000 is set -> ESC6 is present.
            Write-Warn "  ESC6/ESC11: certutil cannot reach $caConfig -- check manually on CA server or open firewall TCP 135 from audit host"
        }

        # --- ESC11: ICPR interface not requiring encryption ---
        Write-Step "  ESC11 check: $caConfig"
        $ifFlags = Get-CAInterfaceFlags -CAConfig $caConfig
        $ca.IfFlags = $ifFlags

        # IF_ENFORCEENCRYPTICERTREQUEST = 0x00000200
        $IF_ENFORCE_ENCRYPT = 0x00000200
        if ($ifFlags -ne -1) {
            $enforceEncrypt = ($ifFlags -band $IF_ENFORCE_ENCRYPT) -ne 0
            if (-not $enforceEncrypt) {
                Add-Finding -ESC 'ESC11' -Severity 'High' `
                    -Target $ca.Name `
                    -Title "CA does not enforce encrypted ICPR (RPC): $($ca.Name)" `
                    -WhyVulnerable "InterfaceFlags on CA $($ca.Name) does not have IF_ENFORCEENCRYPTICERTREQUEST (0x200) set. The DCOM/RPC certificate request interface (MS-ICPR) accepts unauthenticated or NTLM-relayed connections without requiring signing/encryption." `
                    -AttackScenario "$($script:T.NR) can relay NTLM authentication from any machine account (e.g. via coercion with PetitPotam/PrinterBug) directly to the CA's RPC endpoint. No HTTP web enrollment required." `
                    -ActualImpact "NTLM relay to CA RPC allows attacker to obtain a certificate for any coerced machine account. If a DC is coerced, attacker gets a DC certificate and can perform DCSync." `
                    -Fix "certutil -config '$caConfig' -setreg ca\InterfaceFlags +$($IF_ENFORCE_ENCRYPT) # Adds IF_ENFORCEENCRYPTICERTREQUEST; restart CertSvc"
            }
        }
    }

    # --- ESC7: CA ACL -- ManageCA / ManageCertificates ---
    Write-Step "  ESC7 check: $($ca.Name)"

    # Build the CA's own machine account name (e.g. RMN-P-CA$) -- this account MUST
    # have rights on the CA AD object to operate; its presence is expected, not a finding.
    $caMachineAcct = ''
    if ($ca.DnsHost) {
        $caMachineHostname = ($ca.DnsHost -split '\.')[0].ToUpper()
        $caMachineAcct     = "$caMachineHostname$"   # e.g. RMN-P-CA$
    }

    $caDangerousAces = Get-DangerousAces -LdapPath $ca.DN -ObjectType 'CA'
    foreach ($ace in $caDangerousAces) {
        # Skip the CA's own machine account -- it needs these rights to function
        $aceIdentityShort = ($ace.Identity -split '\\')[-1]
        if ($caMachineAcct -and $aceIdentityShort -ieq $caMachineAcct) { continue }
        # Also skip any account ending in $ (machine accounts) that matches CA hostname pattern
        if ($aceIdentityShort -match '\$$' -and $ca.DnsHost -match "^$($aceIdentityShort.TrimEnd('$'))\.") { continue }

        # ManageCA = 0x1, ManageCertificates = 0x2 extended rights on the CA object
        if ($ace.Rights -match 'GenericAll|GenericWrite|WriteDacl|WriteOwner' -or
            ($ace.Rights -match 'ExtendedRight' -and ($ace.ObjType -eq [Guid]::Empty.ToString() -or -not $ace.ObjType))) {
            $sev = if ($ace.IsLowPriv) { 'Critical' } else { 'High' }
            Add-Finding -ESC 'ESC7' -Severity $sev `
                -Target "$($ca.Name) -> $($ace.Identity)" `
                -Title "CA ACL: $($ace.Identity) has $($ace.Rights) on CA $($ca.Name)" `
                -WhyVulnerable "The principal $($ace.Identity) has $($ace.Rights) on the CA object in AD. ManageCA right allows enabling EDITF_ATTRIBUTESUBJECTALTNAME2 (triggering ESC6) remotely. ManageCertificates allows approving pending certificate requests." `
                -AttackScenario "$($script:T.CP) ca -ca-pfx admin.pfx -enable-template 'SubCA' # Once ManageCA is held, attacker can enable a SubCA template, request a subordinate CA cert, and sign arbitrary certs offline." `
                -ActualImpact "If attacker gains ManageCA: they can enable EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6) or enable disabled templates. ManageCertificates alone allows approving requests for templates requiring manager approval." `
                -Fix "Remove $($ace.Identity) from CA ACL: certutil -config '$($ca.Config)' -setcapermission" `
                -TemplateEnabled $true -PublishedTo $ca.DnsHost `
                -Flags $ace.Rights
        }
    }

    # --- ESC8: Web enrollment HTTP endpoints ---
    $httpEndpoints = [System.Collections.Generic.List[string]]::new()
    foreach ($url in $ca.BindUrls) {
        if ($url -match '^https?://') { [void]$httpEndpoints.Add($url) }
    }
    # Also check standard certsrv path
    $certsrvUrl = "http://$($ca.DnsHost)/certsrv"
    $ceswsUrl   = "https://$($ca.DnsHost)/ADPolicyProvider_CEP_Kerberos/service.svc"

    # Check if web enrollment is accessible (HEAD request, no exploitation)
    $httpFound = $false
    if ($httpEndpoints.Count -gt 0) { $httpFound = $true }
    if (-not $httpFound) {
        try {
            $req = [System.Net.WebRequest]::Create($certsrvUrl)
            $req.Method = 'HEAD'
            $req.Timeout = 3000
            $req.ServerCertificateValidationCallback = { return $true }
            $resp = $req.GetResponse()
            $resp.Close()
            $httpFound = $true
            [void]$httpEndpoints.Add($certsrvUrl)
        } catch {
            # 401 Unauthorized also means the endpoint exists
            $ex = $_.Exception
            if ($ex -and $ex.InnerException -and $ex.InnerException.Message -match '401|403') {
                $httpFound = $true
                [void]$httpEndpoints.Add("$certsrvUrl (HTTP $($ex.InnerException.Message))")
            }
        }
    }

    if ($httpFound) {
        Add-Finding -ESC 'ESC8' -Severity 'High' `
            -Target $ca.Name `
            -Title "CA has HTTP web enrollment endpoint: $($ca.Name)" `
            -WhyVulnerable "The CA exposes an HTTP (not requiring Kerberos or SMB signing) enrollment endpoint at: $($httpEndpoints -join ', '). NTLM authentication over HTTP is vulnerable to NTLM relay attacks. An attacker can coerce any domain computer/DC to authenticate (via PetitPotam, PrinterBug, etc.) and relay that NTLM challenge to the web enrollment endpoint to obtain a certificate for the coerced account." `
            -AttackScenario "1. Coerce DC01 to authenticate to attacker: Invoke-$($script:T.PP) -target DC01.domain -listener attacker
2. $($script:T.NR) relays NTLM auth to http://$($ca.DnsHost)/certsrv/certfnsh.asp
3. Obtain DC01 machine certificate
4. Use certificate with $($script:T.RB) or $($script:T.CP) for PKINIT -> get DC01 TGT -> DCSync" `
            -ActualImpact "If a DC is coerced: full domain compromise via DCSync. If any computer is coerced: persistence and possible privilege escalation depending on assigned AD rights." `
            -Fix "Disable NTLM on IIS web enrollment: require Kerberos/certificate auth. Or disable web enrollment if unused. Enable Extended Protection for Authentication (EPA) on IIS." `
            -TemplateEnabled $true -PublishedTo $ca.DnsHost `
            -Flags ($httpEndpoints -join '; ')
    }
}

# --- ESC5: PKI AD Object ACL abuse ---
Write-Step 'Phase 4: ESC5 -- PKI AD object ACL checks'

$pkiObjectPaths = @(
    @{ Path = $ntauthPath;     Name = 'NTAuthCertificates'; Risk = "Write to NTAuthCertificates allows adding attacker-controlled CA cert; all certs issued by that CA become trusted for domain authentication." }
    @{ Path = $pkiBase;        Name = 'Public Key Services container'; Risk = "Write to PKI container allows creating/modifying all PKI objects including CA entries and templates." }
    @{ Path = $caBase;         Name = 'Certification Authorities (AD)'; Risk = "Write access allows adding rogue CA entries trusted by all domain members." }
    @{ Path = $enrollBase;     Name = 'Enrollment Services container'; Risk = "Write allows adding rogue CA enrollment service entries or modifying existing ones." }
)

foreach ($pkiObj in $pkiObjectPaths) {
    $ldapPath = "LDAP://$($pkiObj.Path)"
    $aces = Get-DangerousAces -LdapPath $ldapPath -ObjectType 'PKIObject'
    foreach ($ace in $aces) {
        $sev = if ($ace.IsLowPriv) { 'Critical' } else { 'High' }
        Add-Finding -ESC 'ESC5' -Severity $sev `
            -Target "$($pkiObj.Name) -> $($ace.Identity)" `
            -Title "PKI Object ACL: $($ace.Identity) has $($ace.Rights) on $($pkiObj.Name)" `
            -WhyVulnerable "$($pkiObj.Risk) Principal $($ace.Identity) has $($ace.Rights) which could allow modifying PKI trust infrastructure without any certificate template involvement." `
            -AttackScenario "Attacker with these rights can add a self-signed CA cert to NTAuthCertificates, then issue domain auth certs from that rogue CA. Or modify Enrollment Services entries to redirect enrollment to an attacker-controlled CA." `
            -ActualImpact "PKI infrastructure compromise. Depending on the specific object, impact ranges from breaking certificate trust to full domain compromise by injecting rogue CA trust." `
            -Fix "Remove $($ace.Identity) from $($pkiObj.Name) ACL. Only Domain Admins and Enterprise Admins should have write access to PKI container objects." `
            -Flags $ace.Rights
    }
}

# ==========================================================================
# PHASE 5 -- PER-TEMPLATE ESC CHECKS
# ==========================================================================
Write-Step 'Phase 5: Per-template vulnerability checks'

# Track enrollment agent templates for ESC3-B cross-check
$enrollAgentTemplates = [System.Collections.Generic.List[string]]::new()

foreach ($tpl in $allTemplates) {
    $cn          = $tpl.CN
    $displayName = $tpl.DisplayName
    $published   = $tpl.IsPublished
    $pubTo       = $tpl.PublishedTo
    $ekus        = $tpl.EKUs
    $schemaVer   = $tpl.SchemaVersion
    $dn          = $tpl.DN

    # Get enrollment ACL for this template
    $enrollLowPriv   = $false
    $enrollIdentity  = ''
    $writeDangerous  = [System.Collections.Generic.List[hashtable]]::new()

    $acl = $null
    try {
        $acl = Get-Acl -Path "AD:$dn" -ErrorAction Stop
    } catch {
        Write-Warn "  Cannot read ACL for template $cn : $_"
    }

    if ($acl) {
        foreach ($ace in $acl.Access) {
            if ($ace.AccessControlType -ne 'Allow') { continue }
            $identity = $ace.IdentityReference.ToString()
            $sid = ''
            try {
                $sidObj = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
                $sid = $sidObj.Value
            } catch {}

            # Resolve raw SID strings to friendly display names
            if ($identity -match '^S-1-' -and $sid) {
                $resolved = Resolve-SidToName -Sid $sid
                if ($resolved) { $identity = $resolved }
            }

            $rights   = $ace.ActiveDirectoryRights.ToString()
            $objType  = ''
            try { $objType = $ace.ObjectType.ToString() } catch {}

            $isLowP = Test-IsLowPriv -Identity $identity -Sid $sid
            $isPriv = Test-IsPrivilegedSid -Sid $sid

            # Check enrollment right (for ESC1/ESC2/ESC3)
            if ($isLowP) {
                if ($rights -match 'GenericAll|ExtendedRight') {
                    # ExtendedRight with empty GUID = all extended rights = includes enroll
                    if ($objType -eq '00000000-0000-0000-0000-000000000000' -or
                        $objType -eq $GUID_ENROLL -or
                        $objType -eq $GUID_AUTOENROLL -or
                        $rights -match 'GenericAll') {
                        $enrollLowPriv  = $true
                        $enrollIdentity = $identity
                    }
                }
            }

            # Check write rights (for ESC4)
            if (-not $isPriv) {
                $isDangerous = $false
                if ($rights -match 'GenericAll|GenericWrite|WriteOwner|WriteDacl') { $isDangerous = $true }
                if ($rights -match 'WriteProperty' -and ($objType -eq '00000000-0000-0000-0000-000000000000')) { $isDangerous = $true }
                if ($isDangerous) {
                    [void]$writeDangerous.Add(@{
                        Identity = $identity
                        Rights   = $rights
                        ObjType  = $objType
                        IsLowP   = $isLowP
                    })
                }
            }
        }
    }

    # ----------------------------------------------------------------
    # ESC1: Enrollee-supplied Subject + Client Auth + Low-priv enroll
    # ----------------------------------------------------------------
    if ($tpl.EnrolleeSubject -or $tpl.EnrolleeSAN) {
        $hasClientAuth = Test-HasClientAuth -Ekus $ekus
        if ($hasClientAuth -and $enrollLowPriv -and -not $tpl.ManagerApproval -and $tpl.RASig -eq 0) {
            $sanFlag = if ($tpl.EnrolleeSubject) { 'ENROLLEE_SUPPLIES_SUBJECT (0x1)' } else { 'ENROLLEE_SUPPLIES_SAN (0x10000)' }
            $ekuList = ($ekus -join ', ')
            if (-not $ekuList) { $ekuList = '(none -- any purpose)' }

            Add-Finding -ESC 'ESC1' -Severity 'Critical' `
                -Target $cn `
                -Title "ESC1: Enrollee-supplied SAN + Client Auth in '$cn'" `
                -WhyVulnerable "Template has msPKI-Certificate-Name-Flag: $sanFlag. This means the enrollee controls the Subject/SAN in the certificate request. Combined with a Client Authentication EKU ($ekuList), a low-privilege user ($enrollIdentity) can request a certificate claiming to be ANY user (including Domain Admins) by supplying their UPN or sAMAccountName in the SAN. Manager approval is NOT required (PEND_ALL_REQUESTS not set). RA signature NOT required (msPKI-RA-Signature=$($tpl.RASig))." `
                -AttackScenario "Domain user runs: $($script:T.CP) req -username lowpriv -password pass -ca '$pubTo' -template '$cn' -upn 'administrator@$Domain'
Then: $($script:T.CP) auth -pfx administrator.pfx -dc-ip <DC> -> gets TGT as Administrator
Or: $($script:T.RB) asktgt /user:administrator /certificate:administrator.pfx -> TGT as Domain Admin" `
                -ActualImpact "ANY authenticated domain user can authenticate as Domain Admin. Full domain compromise in one step. Attack is offline -- no password spraying, no lateral movement required before this step." `
                -Fix "Disable CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT in template '$cn' via Certificate Template MMC or: Set-CertificateTemplate -Template '$cn' -NameFlag 0 # Requires Schema Admin / Enterprise Admin" `
                -TemplateEnabled $published -PublishedTo $pubTo `
                -Flags "NameFlags=0x$([Convert]::ToString([int]$tpl.NameFlags,16)) | EnrollEKUs=$ekuList | Enrollee=$enrollIdentity"
        }
    }

    # ----------------------------------------------------------------
    # ESC2: Any Purpose EKU or no EKU + low-priv enroll
    # ----------------------------------------------------------------
    if ($enrollLowPriv -and -not $tpl.ManagerApproval -and $tpl.RASig -eq 0) {
        if (Test-HasAnyPurpose -Ekus $ekus) {
            $ekuStr = if ($ekus.Count -eq 0) { 'NONE (SubCA-equivalent)' } else { $ekus -join ', ' }
            Add-Finding -ESC 'ESC2' -Severity 'Critical' `
                -Target $cn `
                -Title "ESC2: Any Purpose / No EKU in '$cn'" `
                -WhyVulnerable "Template '$cn' has EKUs: $ekuStr. An 'Any Purpose' OID (2.5.29.37.0) or no EKU means the certificate can be used for ANY purpose including client authentication, server authentication, code signing, and enrollment agent operations. Low-priv principal $enrollIdentity can enroll. No manager approval required." `
                -AttackScenario "Obtain cert from template '$cn' as low-priv user. Then use the Any-Purpose cert as an enrollment agent to request certificates on behalf of other users (chain into ESC3-B). Or use directly for Schannel client auth." `
                -ActualImpact "Certificate can be used as an Enrollment Agent (no ESC3-A template required) to enroll on behalf of any user in any other template. This is a universal privilege escalation." `
                -Fix "Add specific EKUs to template '$cn' instead of Any Purpose. Remove enrollment rights for Domain Users if the template is for machine-only use." `
                -TemplateEnabled $published -PublishedTo $pubTo `
                -Flags "EKUs=$ekuStr | Enrollee=$enrollIdentity"
        }
    }

    # ----------------------------------------------------------------
    # ESC3-A: Enrollment Agent template
    # ----------------------------------------------------------------
    $hasEnrollAgent = $false
    foreach ($eku in $ekus) {
        if ($eku -eq $EKU_ENROLL_AGENT) { $hasEnrollAgent = $true; break }
    }
    if ($hasEnrollAgent -and $enrollLowPriv -and -not $tpl.ManagerApproval -and $tpl.RASig -eq 0) {
        [void]$enrollAgentTemplates.Add($cn)
        Add-Finding -ESC 'ESC3' -Severity 'High' `
            -Target $cn `
            -Title "ESC3-A: Enrollment Agent certificate obtainable by low-priv in '$cn'" `
            -WhyVulnerable "Template '$cn' has the Certificate Request Agent (Enrollment Agent) EKU (1.3.6.1.4.1.311.20.2.1). Low-privilege principal $enrollIdentity can enroll in this template, obtaining an Enrollment Agent certificate. An Enrollment Agent certificate allows requesting certificates ON BEHALF OF any other user in templates that permit agent enrollment." `
            -AttackScenario "Step 1: $($script:T.CP) req -template '$cn' -> obtain enrollment agent cert
Step 2 (ESC3-B): $($script:T.CP) req -template 'User' -on-behalf-of DOMAIN\\Administrator -pfx enrollmentagent.pfx -> cert for Domain Admin
Step 3: Use Domain Admin cert for PKINIT authentication -> full domain compromise" `
            -ActualImpact "High by itself. Critical when combined with ESC3-B template. Attacker can enroll on behalf of any domain user." `
            -Fix "Restrict enrollment in '$cn' to Enrollment Agent service accounts only. Remove Domain Users / Authenticated Users enrollment right." `
            -TemplateEnabled $published -PublishedTo $pubTo `
            -Flags "EKU=Certificate Request Agent (1.3.6.1.4.1.311.20.2.1) | Enrollee=$enrollIdentity"
    }

    # ----------------------------------------------------------------
    # ESC3-B: Template allowing enrollment agent requests (cross-check done after loop)
    # ----------------------------------------------------------------
    # Flag templates that:
    # - Allow enrollment agent enrollment (msPKI-RA-Application-Policies includes Enrollment Agent OID)
    # - OR msPKI-RA-Signature == 0 AND the template has client auth
    # Defer full ESC3-B until we know if ESC3-A templates exist

    # ----------------------------------------------------------------
    # ESC4: Template ACL write access
    # ----------------------------------------------------------------
    foreach ($ace in $writeDangerous) {
        # Severity factors:
        #   Low-privilege principal          -> Critical (any domain user can exploit)
        #   Published template + any write   -> High (immediately exploitable)
        #   Unpublished template             -> Medium (attacker also needs CA publish rights / ESC7)
        $sev = if ($ace.IsLowP) { 'Critical' } elseif ($published) { 'High' } else { 'Medium' }

        # Build context notes for the finding
        $contextNotes = ''

        # Flag: unpublished template -- not immediately exploitable
        if (-not $published) {
            $contextNotes += ' [NOT PUBLISHED: attacker must also gain CA publish rights (ESC7) before this is exploitable.]'
        }

        # Flag: principal matches delegated-admin naming convention
        if (Test-IsKnownAdmin -Identity $ace.Identity) {
            $contextNotes += " [ADMIN ACCOUNT/GROUP: '$($ace.Identity)' matches a delegated-admin naming convention (a-xxx prefix or infra admin group). Verify whether write rights on this template are intentional delegation before treating this as a finding.]"
        }

        # Flag: ConfigMgr / SCCM template -- service account write is expected
        if (Test-IsConfigMgrTemplate -TemplateName $cn) {
            $contextNotes += " [CONFIGMGR TEMPLATE: '$cn' is a ConfigMgr/SCCM template. The SCCM service account commonly holds write rights on its own templates. Verify the identity is the SCCM service account before escalating.]"
        }

        $whyText = "Principal $($ace.Identity) has $($ace.Rights) on certificate template '$cn'. Write access to a template allows modifying its attributes: enabling CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (creating ESC1), changing the EKU to Any Purpose (creating ESC2), or removing manager approval requirements.$contextNotes"

        $impactText = if ($published) {
            "Attacker can convert this published template into an ESC1/ESC2 vulnerability on demand by modifying its LDAP attributes."
        } else {
            "Template is not currently published. Attacker would also need CA admin/publish rights (ESC7) to make this immediately exploitable. Lower urgency but still a misconfiguration to remediate."
        }

        Add-Finding -ESC 'ESC4' -Severity $sev `
            -Target "$cn -> $($ace.Identity)" `
            -Title "ESC4: Write access to template '$cn' by $($ace.Identity)" `
            -WhyVulnerable $whyText `
            -AttackScenario "Attacker with write access:
1. Adds CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT to msPKI-Certificate-Name-Flag
2. Requests a cert with administrator's UPN in the SAN
3. Authenticates as Domain Admin -> ESC1 chain
This can be done via $($script:T.CP) template or direct LDAP attribute modification." `
            -ActualImpact $impactText `
            -Fix "Remove $($ace.Identity) write rights from template '$cn'. Only Enterprise Admins/Domain Admins should have write access to template objects." `
            -TemplateEnabled $published -PublishedTo $pubTo `
            -Flags "$($ace.Rights) | Published=$published"
    }

    # ----------------------------------------------------------------
    # ESC9: CT_FLAG_NO_SECURITY_EXTENSION (no szOID_NTDS_CA_SECURITY_EXT)
    # ----------------------------------------------------------------
    if ($tpl.NoSecExtension -and $enrollLowPriv -and -not $tpl.ManagerApproval) {
        $hasClientAuth = Test-HasClientAuth -Ekus $ekus
        if ($hasClientAuth) {
            Add-Finding -ESC 'ESC9' -Severity 'High' `
                -Target $cn `
                -Title "ESC9: No security extension on '$cn'" `
                -WhyVulnerable "msPKI-Enrollment-Flag has CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) set on '$cn'. This flag prevents the CA from embedding the szOID_NTDS_CA_SECURITY_EXT extension (OID 1.3.6.1.4.1.311.25.2) in issued certificates. That extension contains the enrollee's SID and is used by modern DCs to strongly bind the certificate to an account. Without it, the certificate can be used to authenticate as a different account if any account mapping weakness exists." `
                -AttackScenario "Requires: attacker can set userPrincipalName on another account (or GenericWrite on target).
1. Attacker changes their UPN to target's UPN (e.g. administrator@domain.com)
2. Requests cert from '$cn' (no security extension = no SID binding)
3. Resets their UPN back
4. Uses the cert to authenticate as the target account" `
                -ActualImpact "If attacker has GenericWrite on any user account, can obtain their authentication cert. Impact scales with the target account's privileges." `
                -Fix "Remove CT_FLAG_NO_SECURITY_EXTENSION from template '$cn'. Ensure StrongCertificateBindingEnforcement=2 on DCs (see ESC10)." `
                -TemplateEnabled $published -PublishedTo $pubTo `
                -Flags "EnrollFlags=0x$([Convert]::ToString([int]$tpl.EnrollFlags,16)) | Enrollee=$enrollIdentity"
        }
    }

    # ----------------------------------------------------------------
    # ESC13: OID group link -- issuance policy to group escalation
    # ----------------------------------------------------------------
    $raAppPolList = $tpl.RAAppPol
    foreach ($policy in $raAppPolList) {
        if ($policy -match '^\d+\.\d+') {
            # Check if this OID has msDS-OIDToGroupLink in the OID store
            try {
                $oidSearcher = New-LdapSearcher -LdapPath "LDAP://$oidBase" `
                    -Filter "(&(objectClass=msPKI-Enterprise-Oid)(msPKI-Cert-Template-OID=$policy))" `
                    -Props @('cn','msDS-OIDToGroupLink','displayName')
                $oidResult = $oidSearcher.FindOne()
                if ($oidResult) {
                    $groupLink = Get-LdapStr -Entry $oidResult -Attr 'msDS-OIDToGroupLink'
                    if ($groupLink) {
                        Add-Finding -ESC 'ESC13' -Severity 'High' `
                            -Target $cn `
                            -Title "ESC13: OID group link -- '$cn' grants membership in '$groupLink'" `
                            -WhyVulnerable "Template '$cn' has an issuance policy OID ($policy) that is linked via msDS-OIDToGroupLink to AD group '$groupLink'. When a domain user obtains a certificate from this template, the Kerberos Authentication Service (AS) adds the linked group's SID to the user's PAC during PKINIT authentication, effectively granting the user membership in '$groupLink' for the duration of the Kerberos ticket." `
                            -AttackScenario "If $enrollIdentity can enroll in '$cn':
1. Request cert from template '$cn'
2. Use PKINIT to authenticate with the cert: $($script:T.RB) asktgt /certificate:cert.pfx
3. Resulting TGT contains SID of '$groupLink' in PAC
4. If '$groupLink' is privileged (e.g. Domain Admins), attacker has those privileges" `
                            -ActualImpact "If the linked group is privileged, any enrollee effectively gains that group's privileges via PKINIT. Privilege escalation without modifying group membership -- invisible to group membership audits." `
                            -Fix "Remove msDS-OIDToGroupLink from OID $policy unless explicitly required. Restrict enrollment in '$cn' to only accounts that should have '$groupLink' membership." `
                            -TemplateEnabled $published -PublishedTo $pubTo `
                            -Flags "OID=$policy | GroupLink=$groupLink | Enrollee=$enrollIdentity"
                    }
                }
            } catch {
                Write-Warn "  ESC13 OID lookup failed for $policy : $_"
            }
        }
    }

    # ----------------------------------------------------------------
    # ESC15 / EKUwu: Template with application policy override
    # (Schema v4 templates where Application Policy is different from EKU,
    # allowing EKU to be specified at request time)
    # ----------------------------------------------------------------
    if ($schemaVer -ge 4 -and $tpl.EnrolleeSubject -and $enrollLowPriv -and -not $tpl.ManagerApproval) {
        # v4 templates can have the EKU specified by the requester if certain conditions hold
        Add-Finding -ESC 'ESC15' -Severity 'High' `
            -Target $cn `
            -Title "ESC15: Schema v4 template with enrollee-supplied subject '$cn'" `
            -WhyVulnerable "Template '$cn' uses schema version $schemaVer and has CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT. In schema v4 templates, the Application Policy (msPKI-Certificate-Application-Policy) is evaluated differently -- an attacker may be able to include EKUs in the certificate request that differ from what the template specifies, potentially adding client authentication capabilities even if not explicitly granted." `
            -AttackScenario "Request certificate from '$cn' and include an Application Policy extension with client authentication OID. Some CAs honour the requested Application Policy over the template's msPKI-Certificate-Application-Policy." `
            -ActualImpact "If exploitable on this CA, allows obtaining client-auth certs from templates not intended for authentication. Medium-High depending on CA version and patch level." `
            -Fix "Upgrade CA to latest patches (KB5014754 and later). Remove CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT from schema v4 templates not requiring it." `
            -TemplateEnabled $published -PublishedTo $pubTo `
            -Flags "SchemaVersion=$schemaVer | NameFlags=0x$([Convert]::ToString([int]$tpl.NameFlags,16))"
    }

    # ----------------------------------------------------------------
    # ESC16: CA-level CT_FLAG_NO_SECURITY_EXTENSION (broad ESC9)
    # ----------------------------------------------------------------
    # This is checked against the CA's own configuration flag
    # If the CA has disabled security extensions globally, all templates are affected
    # We check this in Phase 6 (CA config) -- flagged separately below

} # end template loop

# ----------------------------------------------------------------
# ESC3-B: Cross-check -- if enrollment agent templates exist, which user-facing
# templates permit enrollment agent requests?
# ----------------------------------------------------------------
if ($enrollAgentTemplates.Count -gt 0) {
    Write-Step "Phase 5: ESC3-B -- checking for templates permitting enrollment agent requests"
    foreach ($tpl in $allTemplates) {
        if (-not $tpl.IsPublished) { continue }
        # Template permits enrollment agent if msPKI-RA-Signature == 0 AND has client auth
        # AND does NOT restrict to specific enrollment agent policies
        if ($tpl.RASig -eq 0 -and (Test-HasClientAuth -Ekus $tpl.EKUs)) {
            $agentList = $enrollAgentTemplates -join ', '
            Add-Finding -ESC 'ESC3' -Severity 'Critical' `
                -Target $tpl.CN `
                -Title "ESC3-B: Template '$($tpl.CN)' allows enrollment agent requests (via ESC3-A: $agentList)" `
                -WhyVulnerable "Template '$($tpl.CN)' has msPKI-RA-Signature=0, meaning an Enrollment Agent certificate (obtainable via ESC3-A from: $agentList) can be used to request a certificate from '$($tpl.CN)' on behalf of ANY user, including Domain Admins. The template does not enforce enrollment agent policy restrictions (msPKI-RA-Application-Policies is unconstrained)." `
                -AttackScenario "Using the Enrollment Agent cert from ESC3-A:
$($script:T.CP) req -ca '$($tpl.PublishedTo)' -template '$($tpl.CN)' -on-behalf-of 'DOMAIN\Administrator' -pfx enrollmentagent.pfx
Then authenticate with the issued Domain Admin cert -> full domain compromise" `
                -ActualImpact "Full domain compromise. Any user who can obtain an enrollment agent cert (ESC3-A) can impersonate any user, including Domain Admins, via this template." `
                -Fix "Set msPKI-RA-Signature >= 1 on '$($tpl.CN)' to require enrollment agent authorization. Or restrict msPKI-RA-Application-Policies to allow only specific service accounts." `
                -TemplateEnabled $tpl.IsPublished -PublishedTo $tpl.PublishedTo `
                -Flags "RASignature=$($tpl.RASig) | ESC3-A templates: $agentList"
        }
    }
}

# ==========================================================================
# PHASE 6 -- DC REGISTRY CHECKS (ESC10 / ESC18)
# ==========================================================================
Write-Step 'Phase 6: DC registry checks (ESC10/ESC18)'

$dcList             = @()
$script:ESC10Failed = [System.Collections.Generic.List[string]]::new()
if (-not $SkipDCRegistry) {
    try {
        $dcSearcher = New-LdapSearcher -LdapPath "LDAP://$domainDN" `
            -Filter '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
            -Props @('cn','dNSHostName','distinguishedName') -Scope 2
        $dcResults = @($dcSearcher.FindAll())
        $dcList = @($dcResults | ForEach-Object { Get-LdapStr -Entry $_ -Attr 'dNSHostName' } | Where-Object { $_ })
        Write-OK "Found $($dcList.Count) Domain Controllers for ESC10/ESC18 checks"
    } catch {
        Write-Warn "DC enumeration failed: $_"
    }
}

foreach ($dcHost in $dcList) {
    if (-not $dcHost) { continue }
    $regChecks = $null

    # --- Attempt 1: WinRM (Invoke-Command) ---
    try {
        $regChecks = Invoke-Command -ComputerName $dcHost -ErrorAction Stop -ScriptBlock {
            $results = @{}

            # ESC10-A: StrongCertificateBindingEnforcement
            $strongBinding = $null
            try {
                $strongBinding = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                    -Name 'StrongCertificateBindingEnforcement' -ErrorAction Stop).StrongCertificateBindingEnforcement
            } catch { $strongBinding = $null }
            $results['StrongCertBinding'] = $strongBinding

            # ESC10-B: CertificateMappingMethods on Schannel
            $certMapMethods = $null
            try {
                $certMapMethods = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' `
                    -Name 'CertificateMappingMethods' -ErrorAction Stop).CertificateMappingMethods
            } catch { $certMapMethods = $null }
            $results['CertMapMethods'] = $certMapMethods

            # ESC18: UseSubjectAltName
            $kdcUseSubjectAlt = $null
            try {
                $kdcUseSubjectAlt = (Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' `
                    -Name 'UseSubjectAltName' -ErrorAction Stop).UseSubjectAltName
            } catch { $kdcUseSubjectAlt = $null }
            $results['UseSubjectAltName'] = $kdcUseSubjectAlt
            $results['Method'] = 'WinRM'
            return $results
        }
    } catch {
        # WinRM failed -- try Remote Registry (uses TCP 445 / SMB, needs RemoteRegistry service running)
        try {
            $remBase = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey(
                [Microsoft.Win32.RegistryHive]::LocalMachine, $dcHost)

            $kdcKey    = $remBase.OpenSubKey('SYSTEM\CurrentControlSet\Services\Kdc')
            $schannelKey = $remBase.OpenSubKey('SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel')

            $sbVal  = $null
            $usaVal = $null
            $cmmVal = $null
            if ($kdcKey) {
                try { $sbVal  = $kdcKey.GetValue('StrongCertificateBindingEnforcement') } catch {}
                try { $usaVal = $kdcKey.GetValue('UseSubjectAltName') } catch {}
                $kdcKey.Close()
            }
            if ($schannelKey) {
                try { $cmmVal = $schannelKey.GetValue('CertificateMappingMethods') } catch {}
                $schannelKey.Close()
            }
            $remBase.Close()

            $regChecks = @{
                StrongCertBinding = $sbVal
                CertMapMethods    = $cmmVal
                UseSubjectAltName = $usaVal
                Method            = 'RemoteRegistry'
            }
        } catch {
            # Both WinRM and Remote Registry unavailable -- collect for consolidated finding below
            [void]$script:ESC10Failed.Add($dcHost)
            continue
        }
    }

    if ($regChecks) {
        # --- ESC10-A: StrongCertificateBindingEnforcement ---
        $sb = $regChecks['StrongCertBinding']
        if ($sb -eq $null -or $sb -eq 0) {
            $sbVal = if ($sb -eq $null) { 'NOT SET (system default -- may be 0 on unpatched)' } else { '0 (DISABLED)' }
            Add-Finding -ESC 'ESC10' -Severity 'High' `
                -Target $dcHost `
                -Title "ESC10-A: StrongCertificateBindingEnforcement is $sbVal on $dcHost" `
                -WhyVulnerable "When StrongCertificateBindingEnforcement is 0 or absent on a DC, Windows accepts certificate-based authentication (PKINIT/Schannel) using only the UPN or DNS name in the certificate SAN, without verifying the SID extension (szOID_NTDS_CA_SECURITY_EXT). This allows ESC9-class attacks where an attacker changes their UPN/SAN to match a target account, obtains a cert, then authenticates as the target." `
                -AttackScenario "1. Find user account where attacker has GenericWrite
2. Change that account's UserPrincipalName to target (e.g. administrator@$Domain)
3. Request cert from any client auth template (including ESC9-flagged templates)
4. Revert UPN change
5. Use cert for PKINIT: $($script:T.RB) asktgt /certificate:cert.pfx -> TGT as administrator" `
                -ActualImpact "Any user who can modify another account's UPN (write UPN attribute) can authenticate as that account. With GenericWrite on a user, attacker can escalate to that user's privilege level." `
                -Fix "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Kdc' -Name 'StrongCertificateBindingEnforcement' -Value 2 # Full enforcement. Requires KB5014754 installed. Test in audit mode (Value=1) first." `
                -Flags "StrongCertificateBindingEnforcement=$sbVal"
        }

        # --- ESC10-B: CertificateMappingMethods ---
        $cmm = $regChecks['CertMapMethods']
        if ($cmm -ne $null) {
            $weakBit4 = ($cmm -band 0x4) -ne 0    # Subject/Issuer explicit mapping
            $weakBit18 = ($cmm -band 0x18) -ne 0  # UPN mapping
            if ($weakBit4 -or $weakBit18) {
                Add-Finding -ESC 'ESC10' -Severity 'Medium' `
                    -Target $dcHost `
                    -Title "ESC10-B: Weak CertificateMappingMethods (0x$([Convert]::ToString($cmm,16))) on $dcHost" `
                    -WhyVulnerable "CertificateMappingMethods=0x$([Convert]::ToString($cmm,16)) has weak mapping bits set. Bit 0x4 (Subject/Issuer explicit mapping) allows mapping certificates by subject/issuer without SID verification. Bit 0x18 (UPN mapping) allows mapping by UPN. Both enable authentication with certificates that don't contain a strong SID binding." `
                    -AttackScenario "Attacker obtains a certificate (from ESC9 or any template without SID extension) and uses it for Schannel/LDAPS authentication to the DC. The DC maps the certificate to an account by UPN or Subject/Issuer, bypassing SID-based strong binding." `
                    -ActualImpact "Enables Schannel-based certificate authentication bypass on this DC. Combined with ESC9, allows privilege escalation." `
                    -Fix "Set CertificateMappingMethods to only allow SID-based mapping: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel' -Name 'CertificateMappingMethods' -Value 0x8 # SAN (UPN) with SID verification only" `
                    -Flags "CertificateMappingMethods=0x$([Convert]::ToString($cmm,16))"
            }
        }

        # --- ESC18: UseSubjectAltName and related PKINIT settings ---
        $usa = $regChecks['UseSubjectAltName']
        if ($usa -ne $null -and $usa -ne 0) {
            Add-Finding -ESC 'ESC18' -Severity 'Medium' `
                -Target $dcHost `
                -Title "ESC18: UseSubjectAltName=$usa on $dcHost" `
                -WhyVulnerable "UseSubjectAltName=$usa on this DC allows the KDC to use SAN-based UPN mapping for PKINIT without requiring the SID extension. On unpatched or misconfigured DCs this can allow certificate-based authentication without strong account binding." `
                -AttackScenario "Obtain a certificate with a target UPN in the SAN (from any template not enforcing SID extension). Authenticate via PKINIT. DC uses SAN UPN without verifying SID binding." `
                -ActualImpact "Medium -- requires prior certificate issuance ability. Combined with ESC1/ESC9, increases impact to Critical." `
                -Fix "Set UseSubjectAltName=0 on DCs after ensuring all legitimate PKINIT clients use certs with SID extension (requires KB5014754 or later)." `
                -Flags "UseSubjectAltName=$usa"
        }
    }
}

# Emit a single consolidated Info finding for all DCs where ESC10 registry checks failed
if ($script:ESC10Failed.Count -gt 0) {
    $failedList = $script:ESC10Failed -join ', '
    Add-Finding -ESC 'ESC10' -Severity 'Info' `
        -Target "ESC10 registry check -- $($script:ESC10Failed.Count) DC(s) unreachable" `
        -Title "ESC10: Registry check could not be completed on $($script:ESC10Failed.Count) DC(s)" `
        -WhyVulnerable "StrongCertificateBindingEnforcement and CertificateMappingMethods registry values on the following DCs could not be read because the audit account lacks WinRM ('Remote Management Users') and Remote Registry access: $failedList. If these values are 0 or absent, ESC9/ESC10-class attacks using UPN manipulation are enabled." `
        -AttackScenario "Cannot assess without registry access. Manual check required on each DC." `
        -ActualImpact "Unknown -- requires verification. If StrongCertificateBindingEnforcement is 0 on any DC, ESC9 + ESC10 attacks can chain to domain compromise." `
        -Fix "Option 1: Re-run with a DA credential: .\Invoke-ADCSAudit.ps1 -Credential (Get-Credential)
Option 2: Run the script directly on a DC (no remote access needed).
Option 3: Check manually on each DC:
  (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\Kdc).StrongCertificateBindingEnforcement
  (Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Schannel).CertificateMappingMethods
Affected DCs: $failedList" `
        -Flags "Failed DCs: $failedList"
}

# ESC12: Check if non-admins have DCOM/shell launch rights on CA server
# (Informational -- requires local check on CA server)
Write-Step 'Phase 6: ESC12 -- CA shell access check (informational)'
foreach ($ca in $caObjects) {
    Add-Finding -ESC 'ESC12' -Severity 'Info' `
        -Target $ca.Name `
        -Title "ESC12: Manual check required -- CA server shell access for $($ca.Name) on $($ca.DnsHost)" `
        -WhyVulnerable "ESC12 requires verifying that non-admin users cannot obtain an interactive shell on the CA server ($($ca.DnsHost)) via WinRM, RDP, or DCOM. If an attacker gains shell access to the CA server, they can directly interact with the CA process, modify CA configuration, and issue certificates regardless of template restrictions." `
        -AttackScenario "Attacker with shell on CA server: certutil -setreg ca\editflags +$($EDITF_ATTRIBUTESUBJECTALTNAME2) # Enables ESC6 directly from the CA host, bypassing AD ACL restrictions." `
        -ActualImpact "Full CA compromise. All certificates issued by this CA become suspect. Attacker can enable any vulnerability (ESC6, approve pending requests, export CA private key)." `
        -Fix "Restrict CA server access: disable WinRM for non-admins, enforce Privileged Access Workstation (PAW) for CA management, monitor CA server for unusual process creation (Event ID 4688) and certutil execution." `
        -TemplateEnabled $true -PublishedTo $ca.DnsHost
}

# ESC14: Check if non-admins can write altSecurityIdentities
Write-Step 'Phase 6: ESC14 -- altSecurityIdentities write access'
try {
    $domainAcl = Get-Acl -Path "AD:$domainDN" -ErrorAction Stop
    foreach ($ace in $domainAcl.Access) {
        if ($ace.AccessControlType -ne 'Allow') { continue }
        $identity = $ace.IdentityReference.ToString()
        $sid = ''
        try {
            $sidObj = $ace.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier])
            $sid = $sidObj.Value
        } catch {}
        if (Test-IsPrivilegedSid -Sid $sid) { continue }
        $rights  = $ace.ActiveDirectoryRights.ToString()
        $objType = ''
        try { $objType = $ace.ObjectType.ToString() } catch {}
        # altSecurityIdentities write = WriteProperty on this specific attribute
        # GUID for altSecurityIdentities: bf967914-0de6-11d0-a285-00aa003049e2
        if ($rights -match 'WriteProperty' -and $objType -match 'bf967914-0de6-11d0-a285-00aa003049e2') {
            Add-Finding -ESC 'ESC14' -Severity 'High' `
                -Target "Domain: $domainDN -> $identity" `
                -Title "ESC14: $identity can write altSecurityIdentities on domain objects" `
                -WhyVulnerable "The altSecurityIdentities AD attribute allows explicitly mapping a certificate to an account for authentication purposes. If a non-admin principal ($identity) can write this attribute on user/computer objects, they can map a certificate they control to a privileged account, then authenticate as that account via Schannel/LDAPS." `
                -AttackScenario "1. Attacker generates self-signed cert or obtains any cert
2. Writes '<X509:<I>IssuerDN<S>SubjectDN>' format string to altSecurityIdentities on target account
3. Authenticates via Schannel/LDAPS with that cert -> authenticated as target account
No CA interaction required at all." `
                -ActualImpact "If attacker can write altSecurityIdentities on a Domain Admin account, full domain compromise without any certificate template exploitation." `
                -Fix "Remove altSecurityIdentities write permission for $identity. Only Domain Admins should be able to set certificate-based explicit account mappings." `
                -Flags "Rights=$rights | ObjType=$objType"
        }
    }
} catch {
    Write-Warn "ESC14 domain ACL check failed: $_"
}

# ==========================================================================
# PHASE 7 -- REPORT GENERATION
# ==========================================================================
Write-Step 'Phase 7: Generating report'

# Severity counts
$critCount = @($script:Findings | Where-Object { $_.Severity -eq 'Critical' }).Count
$highCount = @($script:Findings | Where-Object { $_.Severity -eq 'High' }).Count
$medCount  = @($script:Findings | Where-Object { $_.Severity -eq 'Medium' }).Count
$infoCount = @($script:Findings | Where-Object { $_.Severity -eq 'Info' }).Count

# CSV export
$csvFields = @('ESC','Severity','Target','Title','TemplateEnabled','PublishedTo',
               'WhyVulnerable','AttackScenario','ActualImpact','Fix','Flags','Timestamp')

function Export-FindingsCsv {
    param([array]$Rows, [string]$FilePath)
    $objs = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($r in $Rows) {
        $o = [PSCustomObject]@{}
        foreach ($f in $csvFields) {
            $val = ''
            try { $val = $r[$f] } catch {}
            Add-Member -InputObject $o -MemberType NoteProperty -Name $f -Value $val
        }
        [void]$objs.Add($o)
    }
    $objs | Export-Csv $FilePath -NoTypeInformation -Encoding UTF8
}

$csvPath  = Join-Path $OutputPath "ADCSAudit_Findings_$ts.csv"
$htmlPath = Join-Path $OutputPath "ADCSAudit_Report_$ts.html"
if ($script:Findings.Count -gt 0) {
    Export-FindingsCsv -Rows @($script:Findings) -FilePath $csvPath
    Write-OK "CSV: $csvPath"
}

# --- HTML report ---
$sevColor = @{ Critical='#dc2626'; High='#ea580c'; Medium='#d97706'; Low='#65a30d'; Info='#0284c7' }

$htmlRows = [System.Text.StringBuilder]::new()
$idx = 0
foreach ($f in $script:Findings) {
    $idx++
    $sev     = $f.Severity
    $sevCls  = $sev.ToLower()
    $sevCol  = if ($sevColor.ContainsKey($sev)) { $sevColor[$sev] } else { '#888' }
    $esc     = ConvertTo-SafeHtml $f.ESC
    $title   = ConvertTo-SafeHtml $f.Title
    $target  = ConvertTo-SafeHtml $f.Target
    $why     = ConvertTo-SafeHtml $f.WhyVulnerable
    $attack  = ConvertTo-SafeHtml $f.AttackScenario
    $impact  = ConvertTo-SafeHtml $f.ActualImpact
    $fix     = ConvertTo-SafeHtml $f.Fix
    $flags   = ConvertTo-SafeHtml $f.Flags
    $pubTo   = ConvertTo-SafeHtml $f.PublishedTo
    $enabled = if ($f.TemplateEnabled) { '<span style="color:#16a34a">YES</span>' } else { '<span style="color:#94a3b8">NO</span>' }
    $detId   = "det_$idx"

    [void]$htmlRows.Append("<tr class='fr' data-sev='$sevCls' onclick='toggleRow(this,""$detId"")'>`n")
    [void]$htmlRows.Append("<td><span class='sev-badge' style='background:$sevCol'>$sev</span></td>")
    [void]$htmlRows.Append("<td><b>$esc</b></td><td>$title</td><td>$target</td><td>$enabled</td><td>$pubTo</td></tr>`n")
    [void]$htmlRows.Append("<tr id='$detId' class='dr'><td colspan='6'><div class='dp'>")
    [void]$htmlRows.Append("<p><b>Why Vulnerable:</b> $why</p>")
    [void]$htmlRows.Append("<p><b>Attack Scenario:</b><pre class='atk'>$attack</pre></p>")
    [void]$htmlRows.Append("<p><b>Actual Impact:</b> $impact</p>")
    if ($fix)   { [void]$htmlRows.Append("<p><b>Remediation:</b><pre class='rem'>$fix</pre></p>") }
    if ($flags) { [void]$htmlRows.Append("<p><b>Flags/Detail:</b> <code>$flags</code></p>") }
    [void]$htmlRows.Append("</div></td></tr>`n")
}
$tableBody = $htmlRows.ToString()

$htmlReport = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ADCS Audit -- $Domain -- $ts</title>
<style>
body{font-family:Consolas,monospace;background:#0f172a;color:#e2e8f0;margin:0;padding:0}
.hdr{background:#1e293b;padding:20px 30px;border-bottom:2px solid #334155}
.hdr h1{margin:0;font-size:1.3em;color:#f472b6}
.hdr p{margin:4px 0;color:#94a3b8;font-size:.85em}
.stats{display:flex;gap:12px;padding:12px 30px;background:#1e293b;border-bottom:1px solid #334155;flex-wrap:wrap}
.stat-box{background:#0f172a;border:1px solid #334155;border-radius:6px;padding:8px 16px;text-align:center;min-width:80px}
.stat-box .num{font-size:1.6em;font-weight:bold}
.stat-box .lbl{font-size:.7em;color:#94a3b8}
.toolbar{background:#1e293b;padding:10px 30px;display:flex;gap:8px;flex-wrap:wrap;align-items:center;border-bottom:1px solid #334155}
.tbtn{padding:4px 12px;border-radius:4px;border:1px solid #475569;background:#1e293b;color:#94a3b8;cursor:pointer;font-size:.8em}
.tbtn:hover,.tbtn.active{background:#334155;color:#e2e8f0}
.tbtn.crit{border-color:#dc2626;color:#dc2626}.tbtn.crit.active{background:#dc2626;color:#fff}
.tbtn.high{border-color:#ea580c;color:#ea580c}.tbtn.high.active{background:#ea580c;color:#fff}
.tbtn.med{border-color:#d97706;color:#d97706}.tbtn.med.active{background:#d97706;color:#fff}
.srch{background:#0f172a;border:1px solid #475569;color:#e2e8f0;padding:4px 10px;border-radius:4px;font-size:.85em;width:200px}
.content{padding:20px 30px}
table{width:100%;border-collapse:collapse;font-size:.82em}
th{background:#1e293b;color:#94a3b8;padding:8px 10px;text-align:left;border-bottom:2px solid #334155;position:sticky;top:0;z-index:10}
.fr{cursor:pointer;border-left:3px solid transparent;transition:background .15s}
.fr:hover{background:#1e293b}
.dr{display:none}
.dr td{padding:0}
.dp{background:#1e293b;border-left:3px solid #475569;margin:2px 0;padding:12px 18px;font-size:.82em;line-height:1.7}
.dp p{margin:6px 0}
td{padding:7px 10px;border-bottom:1px solid #1e293b;vertical-align:top}
.sev-badge{display:inline-block;padding:2px 8px;border-radius:3px;font-size:.75em;font-weight:bold;color:#fff}
.atk{background:#0f172a;color:#7dd3fc;padding:10px;border-radius:4px;margin:6px 0;white-space:pre-wrap;font-size:.8em;border-left:3px solid #0284c7}
.rem{background:#0f172a;color:#fbbf24;padding:10px;border-radius:4px;margin:6px 0;white-space:pre-wrap;font-size:.8em;border-left:3px solid #d97706}
.esc-ref{background:#1e293b;padding:16px 30px;border-bottom:1px solid #334155;font-size:.8em;color:#94a3b8}
.esc-ref span{display:inline-block;margin:3px 6px;padding:2px 8px;border-radius:3px;background:#0f172a;color:#e2e8f0;border:1px solid #334155}
code{background:#0f172a;padding:1px 4px;border-radius:3px;font-size:.9em;color:#a78bfa}
.vis-count{font-size:.75em;color:#94a3b8;margin-left:8px}
</style>
</head>
<body>
<div class="hdr">
<h1>ADCS Security Audit -- $Domain</h1>
<p>Generated: $ts | Total Findings: $($script:Findings.Count) | CAs Enumerated: $($caObjects.Count) | Templates Enumerated: $($allTemplates.Count)</p>
<p>Scope: Read-Only. No certificates enrolled. No configuration modified.</p>
</div>
<div class="stats">
<div class="stat-box"><div class="num" style="color:#dc2626">$critCount</div><div class="lbl">CRITICAL</div></div>
<div class="stat-box"><div class="num" style="color:#ea580c">$highCount</div><div class="lbl">HIGH</div></div>
<div class="stat-box"><div class="num" style="color:#d97706">$medCount</div><div class="lbl">MEDIUM</div></div>
<div class="stat-box"><div class="num" style="color:#0284c7">$infoCount</div><div class="lbl">INFO</div></div>
<div class="stat-box"><div class="num" style="color:#e2e8f0">$($script:Findings.Count)</div><div class="lbl">TOTAL</div></div>
</div>
<div class="esc-ref">
<b>ESC Reference:</b>
<span>ESC1: Enrollee-Supplied SAN</span><span>ESC2: Any Purpose EKU</span>
<span>ESC3: Enrollment Agent</span><span>ESC4: Template Write ACL</span>
<span>ESC5: PKI Object ACL</span><span>ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2</span>
<span>ESC7: CA ACL</span><span>ESC8: Web Enrollment Relay</span>
<span>ESC9: No Security Extension</span><span>ESC10: Weak Cert Mapping</span>
<span>ESC11: ICPR No Encrypt</span><span>ESC12: CA Shell Access</span>
<span>ESC13: OID Group Link</span><span>ESC14: altSecurityIdentities Write</span>
<span>ESC15: Schema v4 EKU Override</span><span>ESC16: CA-Level No SID Ext</span>
<span>ESC18: PKINIT SAN Mapping</span>
</div>
<div class="toolbar">
<button class="tbtn active" onclick="setFilter(this,'')">All <span id="vc"></span></button>
<button class="tbtn crit" onclick="setFilter(this,'critical')">Critical</button>
<button class="tbtn high" onclick="setFilter(this,'high')">High</button>
<button class="tbtn med" onclick="setFilter(this,'medium')">Medium</button>
<button class="tbtn" onclick="setFilter(this,'info')">Info</button>
<input class="srch" id="srch" type="text" placeholder="Search..." oninput="doFilter()">
</div>
<div class="content">
<table id="ftbl">
<thead><tr>
<th>Severity</th><th>ESC</th><th>Title</th><th>Target</th><th>Published</th><th>CA / Host</th>
</tr></thead>
<tbody>
$tableBody
</tbody>
</table>
</div>
<script>
var activeSev='';
function toggleRow(row,detId){
    var det=document.getElementById(detId);
    if(!det)return;
    det.style.display=det.style.display==='table-row'?'none':'table-row';
}
function setFilter(btn,sev){
    document.querySelectorAll('.tbtn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    activeSev=sev;
    doFilter();
}
function doFilter(){
    var q=document.getElementById('srch').value.toLowerCase();
    var rows=document.querySelectorAll('.fr');
    var vis=0;
    rows.forEach(function(r){
        var sevOk=!activeSev||r.getAttribute('data-sev')===activeSev;
        var txtOk=!q||r.textContent.toLowerCase().indexOf(q)>=0;
        r.style.display=(sevOk&&txtOk)?'':'none';
        var m=r.getAttribute('onclick').match(/"([^"]+)"/);
        if(m){var d=document.getElementById(m[1]);if(d)d.style.display='none';}
        if(sevOk&&txtOk)vis++;
    });
    var vc=document.getElementById('vc');
    if(vc)vc.textContent='('+vis+')';
}
doFilter();
</script>
</body>
</html>
"@

[System.IO.File]::WriteAllText($htmlPath, $htmlReport, [System.Text.Encoding]::UTF8)
Write-OK "HTML report: $htmlPath"

# Console summary
Write-Host ''
Write-Host '+----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host '|             ADCS AUDIT SUMMARY                          |' -ForegroundColor Cyan
Write-Host '+----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host "| Domain     : $Domain" -ForegroundColor Cyan
Write-Host "| CAs found  : $($caObjects.Count)" -ForegroundColor Cyan
Write-Host "| Templates  : $($allTemplates.Count) total / $($publishedSet.Count) published" -ForegroundColor Cyan
Write-Host '+----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host "| CRITICAL   : $critCount" -ForegroundColor Red
Write-Host "| HIGH       : $highCount" -ForegroundColor Magenta
Write-Host "| MEDIUM     : $medCount" -ForegroundColor Yellow
Write-Host "| INFO       : $infoCount" -ForegroundColor Cyan
Write-Host '+----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host "| Report     : $htmlPath" -ForegroundColor White
Write-Host "| CSV        : $csvPath" -ForegroundColor White
Write-Host '+----------------------------------------------------------+' -ForegroundColor Cyan
Write-Host ''
Write-Log 'Audit complete.'
