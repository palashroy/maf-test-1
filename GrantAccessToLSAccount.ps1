# 1. Target the certificate in the LocalMachine Root store
$cert = Get-ChildItem -Path "Cert:\LocalMachine\Root\272FDEA6F224998F399759914F8E718DC3539DD8"

# 2. Extract the unique name of the private key container
$keyName = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert).Key.UniqueName

# 3. Locate the private key file path on the disk
$keyPath = "${env:ALLUSERSPROFILE}\Microsoft\Crypto\Keys\${keyName}"
if (-not (Test-Path $keyPath)) {
    $keyPath = "${env:ALLUSERSPROFILE}\Microsoft\Crypto\RSA\MachineKeys\${keyName}"
}

# 4. Apply read permissions for the Local Service account
$acl = Get-Acl -Path $keyPath
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule("NT AUTHORITY\LOCAL SERVICE", "Read", "Allow")
$acl.AddAccessRule($accessRule)
Set-Acl -Path $keyPath -AclObject $acl

Write-Host "Read access granted successfully to LocalService." -ForegroundColor Green