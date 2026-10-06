#Requires -RunAsAdministrator

$thumbprint = "272FDEA6F224998F399759914F8E718DC3539DD8".ToUpperInvariant()

# Current user (DOMAIN\User or COMPUTER\User)
$currentUser = "NT AUTHORITY\LOCAL SERVICE"

# Open certificate from LocalMachine\My (thumbprint comparison is case-insensitive, but normalize anyway)
$cert = Get-ChildItem -Path "Cert:\LocalMachine\Root" -ErrorAction Stop |
    Where-Object { $_.Thumbprint -eq $thumbprint }

if (-not $cert) {
    throw "Certificate with thumbprint $thumbprint not found in Cert:\LocalMachine\My."
}

if (-not $cert.HasPrivateKey) {
    throw "Certificate does not have a private key."
}

# Try RSA first, then fall back to ECDSA
$key = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if (-not $key) {
    $key = [System.Security.Cryptography.X509Certificates.ECDsaCertificateExtensions]::GetECDsaPrivateKey($cert)
}

if (-not $key) {
    throw "Unable to obtain a private key handle (unsupported algorithm or inaccessible key)."
}

try {
    if ($key -is [System.Security.Cryptography.RSACng] -or $key -is [System.Security.Cryptography.ECDsaCng]) {
        $keyName = $key.Key.UniqueName
        $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\Keys\$keyName"
    }
    elseif ($key -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
        $keyName = $key.CspKeyContainerInfo.UniqueKeyContainerName
        $keyPath = Join-Path $env:ProgramData "Microsoft\Crypto\RSA\MachineKeys\$keyName"
    }
    else {
        throw "Unsupported private key provider: $($key.GetType().FullName)."
    }
}
finally {
    $key.Dispose()
}

if (-not (Test-Path $keyPath)) {
    throw "Private key file not found: $keyPath"
}

# Grant Read permission
$acl = Get-Acl -Path $keyPath
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    $currentUser,
    [System.Security.AccessControl.FileSystemRights]::Read,
    [System.Security.AccessControl.InheritanceFlags]::None,
    [System.Security.AccessControl.PropagationFlags]::None,
    [System.Security.AccessControl.AccessControlType]::Allow
)

$acl.AddAccessRule($rule)
Set-Acl -Path $keyPath -AclObject $acl

Write-Host "Read access granted to '$currentUser' on certificate private key at '$keyPath'."