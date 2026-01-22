function Protect-String {
    param([string]$PlainText, [string]$Passphrase)
    $plainBytes = [System.Text.Encoding]::UTF8.GetBytes($PlainText)
    $ms = New-Object System.IO.MemoryStream
    $gzip = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Compress)
    $gzip.Write($plainBytes, 0, $plainBytes.Length)
    $gzip.Close()
    $compressedBytes = $ms.ToArray()
    $ms.Close()
    
    $salt = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($salt)
    
    # ULTRA FAST: 200 iterations
    $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 200)
    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $kdf.GetBytes(32)
    $aes.IV = $kdf.GetBytes(16)
    
    $enc = $aes.CreateEncryptor()
    $encBytes = $enc.TransformFinalBlock($compressedBytes, 0, $compressedBytes.Length)
    
    $out = New-Object byte[] ($salt.Length + $encBytes.Length)
    [Array]::Copy($salt, $out, $salt.Length)
    [Array]::Copy($encBytes, 0, $out, $salt.Length, $encBytes.Length)
    
    $enc.Dispose(); $aes.Dispose(); $kdf.Dispose()
    return [Convert]::ToBase64String($out)
}

function Unprotect-String {
    param([string]$CipherBase64, [string]$Passphrase)
    try {
        $inBytes = [Convert]::FromBase64String($CipherBase64)
        $salt = $inBytes[0..15]
        $cipherBytes = $inBytes[16..($inBytes.Length-1)]
        
        $kdf = New-Object System.Security.Cryptography.Rfc2898DeriveBytes($Passphrase, $salt, 200)
        $aes = [System.Security.Cryptography.Aes]::Create()
        $aes.Key = $kdf.GetBytes(32)
        $aes.IV = $kdf.GetBytes(16)
        
        $dec = $aes.CreateDecryptor()
        $compressedBytes = $dec.TransformFinalBlock($cipherBytes, 0, $cipherBytes.Length)
        
        $dec.Dispose(); $aes.Dispose(); $kdf.Dispose()
        
        $ms = New-Object System.IO.MemoryStream
        $ms.Write($compressedBytes, 0, $compressedBytes.Length)
        $ms.Position = 0
        $gzip = New-Object System.IO.Compression.GZipStream($ms, [System.IO.Compression.CompressionMode]::Decompress)
        $outMs = New-Object System.IO.MemoryStream
        $gzip.CopyTo($outMs)
        $gzip.Close()
        $ms.Close()
        
        $result = [System.Text.Encoding]::UTF8.GetString($outMs.ToArray())
        $outMs.Close()
        return $result
    }
    catch {
        return $null
    }
}

function Save-OriginalName {
    param([string]$Name)
    return [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($Name))
}

function Load-OriginalName {
    param([string]$Base64Name)
    try {
        return [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($Base64Name))
    }
    catch {
        return $null
    }
}

function ConvertTo-EncryptedVault {
    param($InputFile, $ProtectedOutputFile, $Passphrase, $OriginalName)
    if (!(Test-Path $InputFile)) { return $false }
    
    $b64 = [convert]::ToBase64String([io.file]::ReadAllBytes($InputFile))
    $protectedData = Protect-String $b64 $Passphrase
    $nameData = Save-OriginalName $OriginalName
    "NAME:$nameData`n$protectedData" | Out-File $ProtectedOutputFile -Encoding UTF8 -Force
    return $true
}

function ConvertFrom-EncryptedVault {
    param($ProtectedInputFile, $OutputFile, $Passphrase)
    if (!(Test-Path $ProtectedInputFile)) { return $false }
    
    $content = Get-Content $ProtectedInputFile -Encoding UTF8 -Raw
    $parts = $content -split "`n", 2
    if ($parts.Length -lt 2) { return $false }
    
    $decoded = Unprotect-String $parts[1] $Passphrase
    if (!$decoded) { return $false }
    
    $bytes = [convert]::FromBase64String($decoded)
    $dir = Split-Path $OutputFile -Parent
    if (!(Test-Path $dir)) { New-Item $dir -ItemType Directory -Force | Out-Null }
    
    [IO.File]::WriteAllBytes($OutputFile, $bytes)
    return $true
}

function Get-OriginalNameFromEncrypted {
    param([string]$EncryptedFile)
    try {
        $content = (Get-Content $EncryptedFile -Encoding UTF8 -Raw) -replace "`n.*", ""
        if ($content -match "^NAME:([A-Za-z0-9+/=]+)$") {
            return Load-OriginalName $matches[1]
        }
    }
    catch {}
    return $null
}

function Get-RandomName {
    $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'
    $name = ''
    for ($i = 0; $i -lt 12; $i++) {
        $name += $chars.Substring((Get-Random -Maximum $chars.Length), 1)
    }
    return "$name.txt"
}

function Invoke-EncryptedVault {
    Clear-Host
    Write-Host "EncryptedVault v1.0 - ULTRA FAST Decryption" -ForegroundColor Green
    Write-Host ("=" * 50) -ForegroundColor Green
    Write-Host ""

    $action = Read-Host "1=Encrypt 2=Decrypt"
    if ($action -ne "1" -and $action -ne "2") { 
        Write-Error "Use 1 or 2 only!"
        return 
    }
    
    $isEncrypt = $action -eq "1"
    $title = if ($isEncrypt) { "Encryption" } else { "Decryption" }
    
    Write-Host "Source Selection" -ForegroundColor Yellow
    $sourceType = Read-Host "1=Single file 2=Folder"
    
    if ($sourceType -eq "1") {
        $sourcePath = Read-Host "Enter path"
        $files = @(Get-Item $sourcePath -ErrorAction SilentlyContinue)
        $isFolder = $false
    } else {
        $sourcePath = Read-Host "Enter folder path"
        $files = Get-ChildItem $sourcePath -Recurse -File -ErrorAction SilentlyContinue
        $isFolder = $true
    }
    
    if (!$files -or $files.Count -eq 0) { 
        Write-Error "No files found!"
        return 
    }
    Write-Host "Found $($files.Count) files" -ForegroundColor Cyan
    
    Write-Host "Destination Selection" -ForegroundColor Yellow
    $destType = Read-Host "1=In-place 2=New folder"
    
    if ($destType -eq "2") {
        $destPath = Read-Host "Enter destination folder"
        if (!(Test-Path $destPath)) { 
            New-Item $destPath -ItemType Directory -Force | Out-Null 
        }
        $inPlace = $false
    } else {
        $destPath = if ($isFolder) { $sourcePath } else { Split-Path $sourcePath }
        $inPlace = $true
    }
    
    $pass = Read-Host "Enter password" -AsSecureString
    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass))
    
    $ok = Read-Host "Confirm $title for $($files.Count) files? (Y/N)"
    if ($ok -ne "Y" -and $ok -ne "y") { 
        Write-Host "Cancelled."
        return 
    }
    
    if ($isFolder -and $inPlace) {
        $backup = "$sourcePath.bak_$(Get-Date -f 'yyyyMMdd_HHmmss')"
        Copy-Item $sourcePath $backup -Recurse -Force
        Write-Host "Backup: $backup" -ForegroundColor Magenta
    }
    
    $count = 0
    $total = $files.Count
    foreach ($file in $files) {
        $percent = [math]::Round(($count / $total) * 100)
        Write-Progress -Activity $title -Status "$count of $total ($percent%)" -PercentComplete $percent
        
        if ($isEncrypt) {
            $newName = Get-RandomName
            $outFile = Join-Path $destPath $newName
            if (ConvertTo-EncryptedVault $file.FullName $outFile $plainPass $file.Name) {
                $count++
                Write-Host "Encrypted: $($file.Name) -> $newName" -ForegroundColor Green
            }
        } else {
            $origName = Get-OriginalNameFromEncrypted $file.FullName
            if (!$origName) { $origName = $file.BaseName }
            $outFile = Join-Path $destPath $origName
            
            if (ConvertFrom-EncryptedVault $file.FullName $outFile $plainPass) {
                $count++
                Write-Host "Decrypted: $($file.Name) -> $origName" -ForegroundColor Cyan
            }
        }
    }
    
    Write-Progress -Completed -Activity "Completed"
    Write-Host "`n$title FINISHED! $count of $total files processed." -ForegroundColor Green
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EncryptedVault
}
