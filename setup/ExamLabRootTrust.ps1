function Get-CertificateSha256([byte[]]$Bytes) {
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try { [BitConverter]::ToString($algorithm.ComputeHash($Bytes)).Replace('-','') }
    finally { $algorithm.Dispose() }
}

function Read-PinnedRoot([string]$Path,[string]$Expected) {
    if ($Expected -notmatch '\A[0-9A-Fa-f]{64}\z') { throw 'Для каждого корневого сертификата требуется проверенный SHA-256.' }
    $file = Get-Item -LiteralPath $Path
    if ($file -isnot [IO.FileInfo] -or $file.Length -gt 16384) { throw 'Ожидался один публичный корневой сертификат DER.' }
    ConvertFrom-PinnedRoot ([IO.File]::ReadAllBytes($file.FullName)) $Expected
}

function ConvertFrom-PinnedRoot([byte[]]$Data,[string]$Expected) {
    if ($Expected -notmatch '\A[0-9A-Fa-f]{64}\z' -or $Data.Length -eq 0 -or $Data.Length -gt 16384) { throw 'Ожидался один публичный корневой сертификат DER с проверенным SHA-256.' }
    if ((Get-CertificateSha256 $data) -ine $Expected) { throw 'Отпечаток файла корневого сертификата отличается от проверенного SHA-256.' }
    ConvertFrom-TrustedRoot $Data
}

function ConvertFrom-TrustedRoot([byte[]]$Data) {
    if ($Data.Length -eq 0 -or $Data.Length -gt 16384) { throw 'Ожидался один публичный корневой сертификат DER.' }
    $x509 = [Security.Cryptography.X509Certificates.X509Certificate2]
    if ($x509::GetCertContentType($data) -ne [Security.Cryptography.X509Certificates.X509ContentType]::Cert) { throw 'Ожидался один публичный сертификат DER.' }
    $certificate = $x509::new($data)
    try {
        $constraints = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.19' })
        $keyUsage = @($certificate.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        $now = Get-Date
        if ($certificate.HasPrivateKey -or [Convert]::ToBase64String($certificate.RawData) -cne [Convert]::ToBase64String($Data) -or
            [Convert]::ToBase64String($certificate.SubjectName.RawData) -cne [Convert]::ToBase64String($certificate.IssuerName.RawData) -or
            $constraints.Count -ne 1 -or -not $constraints[0].CertificateAuthority -or
            ($keyUsage.Count -and -not ($keyUsage[0].KeyUsages -band [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyCertSign)) -or
            $certificate.NotBefore -gt $now -or $certificate.NotAfter -le $now) {
            throw 'Сертификат должен быть действующим публичным корнем CA с разрешением подписывать сертификаты.'
        }
        return $certificate
    } catch { $certificate.Dispose(); throw }
}

function Install-PinnedRoots([Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates) {
    Install-TrustedRoots $Certificates -ReportSha256
}

function Install-TrustedRoots([Security.Cryptography.X509Certificates.X509Certificate2[]]$Certificates,[switch]$ReportSha256) {
    if (-not $Certificates.Count) { return }
    $store = [Security.Cryptography.X509Certificates.X509Store]::new('Root','LocalMachine')
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite -bor [Security.Cryptography.X509Certificates.OpenFlags]::OpenExistingOnly)
        foreach ($certificate in $Certificates) {
            $encoded = [Convert]::ToBase64String($certificate.RawData)
            $matches = @($store.Certificates.Find('FindByThumbprint',$certificate.Thumbprint,$false))
            if (@($matches | Where-Object { [Convert]::ToBase64String($_.RawData) -cne $encoded }).Count) { throw 'В Windows Root найден конфликт отпечатка сертификата.' }
            if (-not $matches.Count) { $store.Add($certificate) }
            $readback = @($store.Certificates.Find('FindByThumbprint',$certificate.Thumbprint,$false) |
                Where-Object { [Convert]::ToBase64String($_.RawData) -ceq $encoded })
            if (-not $readback.Count) { throw 'Корневой сертификат отсутствует при повторном чтении Windows Root.' }
            $result = [ordered]@{ Subject=$certificate.Subject; Added=(-not $matches.Count) }
            if ($ReportSha256) { $result.SHA256 = Get-CertificateSha256 $certificate.RawData }
            [pscustomobject]$result
        }
    } finally { $store.Dispose() }
}
