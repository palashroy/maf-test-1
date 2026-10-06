<#
.SYNOPSIS
    Grants a specified service account (default: NT AUTHORITY\LOCAL SERVICE) read access
    to the private key of a certificate installed in LocalMachine\Root, identified by thumbprint.

.PARAMETER Thumbprint
    The thumbprint of the certificate (spaces allowed, will be stripped).

.PARAMETER Account
    The account to grant read access to. Defaults to 'NT AUTHORITY\LOCAL SERVICE',
    which is the account used by the SE.IA.MAF.Automate360Platform service.

.NOTES
    Must be run elevated (as Administrator).
#>

param(
    [Parameter(Mandatory = $true)]
    [string]$Thumbprint,

    [Parameter(Mandatory = $false)]
    [string]$Account = "NT AUTHORITY\LOCAL SERVICE"
)

# Normalize thumbprint
$Thumbprint = $Thumbprint.Trim().Replace(" ", "").ToUpperInvariant()

# Ensure running elevated
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator."
    exit 1
}

$storeName = "Root"

# Locate the certificate
$cert = Get-ChildItem "Cert:\LocalMachine\$storeName" | Where-Object { $_.Thumbprint -eq $Thumbprint }

if (-not $cert) {
    Write-Error "Certificate with thumbprint '$Thumbprint' not found in LocalMachine\$storeName."
    exit 1
}

if (-not $cert.HasPrivateKey) {
    Write-Error "Certificate with thumbprint '$Thumbprint' does not have an associated private key."
    exit 1
}

Write-Host "Found certificate '$($cert.Subject)'. Resolving private key file..."

$keyFilePath = $null

try {
    $rsaKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)

    if ($rsaKey -is [System.Security.Cryptography.RSACng]) {
        # CNG-backed key (covers both native CNG keys and CAPI keys surfaced through the CNG bridge)
        $cngKey = $rsaKey.Key
        $keyName = $cngKey.UniqueName
        $provider = $cngKey.Provider.Provider

        # Native CNG keys live under ProgramData\Microsoft\Crypto\Keys
        $cngPath = Join-Path "$env:ProgramData\Microsoft\Crypto\Keys" $keyName
        # Legacy CAPI keys (even when wrapped by RSACng) live under RSA\MachineKeys
        $capiPath = Join-Path "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys" $keyName

        if (Test-Path $cngPath) {
            $keyFilePath = $cngPath
        }
        elseif (Test-Path $capiPath) {
            $keyFilePath = $capiPath
        }
        else {
            Write-Host "Key name '$keyName' (provider: $provider) did not match either expected folder directly."
        }
    }
}
catch {
    Write-Host "Error resolving key via RSACng: $($_.Exception.Message)"
}

# Fallback: search both folders for a container name containing the certificate's key container hint
if (-not $keyFilePath) {
    Write-Host "Falling back to container name lookup via certutil..."
    $storeOutput = & certutil -store $storeName $Thumbprint 2>&1
    $containerLine = $storeOutput | Select-String -Pattern "Unique container name:\s*(.+)$"
    if ($containerLine) {
        $containerName = $containerLine.Matches[0].Groups[1].Value.Trim()
        foreach ($basePath in @(
            "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys",
            "$env:ProgramData\Microsoft\Crypto\Keys"
        )) {
            $candidate = Join-Path $basePath $containerName
            if (Test-Path $candidate) {
                $keyFilePath = $candidate
                break
            }
        }
    }
}

if (-not $keyFilePath) {
    Write-Error "Could not locate the private key file on disk for thumbprint '$Thumbprint'."
    exit 1
}

Write-Host "Private key file: $keyFilePath"
Write-Host "Granting read access to '$Account'..."

$icaclsOutput = & icacls $keyFilePath /grant "${Account}:(R)" 2>&1
Write-Host $icaclsOutput

if ($LASTEXITCODE -ne 0) {
    Write-Error "icacls failed with exit code $LASTEXITCODE. See output above for details."
    exit $LASTEXITCODE
}

Write-Host "Successfully granted read access to '$Account' for the private key of certificate '$Thumbprint'." -ForegroundColor Green
Write-Host "Restart the 'SE.IA.MAF.Automate360Platform' service for the change to take effect if it is currently running." -ForegroundColor Yellow