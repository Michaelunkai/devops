# CleanupBackups.ps1
# Disables Macrium Image Guardian (MIG registry) + stops service,
# force-deletes ALL backups in F:\win11recovery, then restores guardian.
# Called by: rmackback (profile function)

$BackupDir   = 'F:\win11recovery'
$migKey      = 'HKLM:\SOFTWARE\Macrium\reflect\MIG'
$verifiedKey = "$migKey\Verified"

# ---- Step 1: Disable Image Guardian via registry ----
Write-Host "[1/5] Disabling Macrium Image Guardian (MIG)..." -ForegroundColor Cyan
$prevEnabled = (Get-ItemProperty $migKey -Name 'Enabled' -EA SilentlyContinue).Enabled
Set-ItemProperty $migKey -Name 'Enabled' -Value 0 -Type DWord -EA SilentlyContinue
# Remove all per-file Protected entries so kernel driver unprotects them
$removedCount = 0
Get-ChildItem $verifiedKey -EA SilentlyContinue | ForEach-Object {
    Remove-Item $_.PSPath -Force -Recurse -EA SilentlyContinue
    $removedCount++
}
Write-Host "    MIG disabled. Cleared $removedCount protected file entries." -ForegroundColor Yellow

# ---- Step 2: Stop MacriumService ----
Write-Host "[2/5] Stopping MacriumService..." -ForegroundColor Cyan
Stop-Service -Name 'MacriumService' -Force -ErrorAction SilentlyContinue
$waited = 0
while ((Get-Service -Name 'MacriumService' -EA SilentlyContinue).Status -ne 'Stopped' -and $waited -lt 15) {
    Start-Sleep -Seconds 1; $waited++
}
Write-Host "    MacriumService: $((Get-Service 'MacriumService' -EA SilentlyContinue).Status)" -ForegroundColor Yellow

# ---- Step 3: Kill lingering Macrium processes ----
Write-Host "[3/5] Killing lingering Macrium processes..." -ForegroundColor Cyan
'mrauto','ReflectBin','Reflect','MacriumBackupMessage' | ForEach-Object {
    $procs = Get-Process -Name $_ -ErrorAction SilentlyContinue
    if ($procs) { $procs | Stop-Process -Force -EA SilentlyContinue; Write-Host "    Killed: $_" -ForegroundColor Yellow }
}
Start-Sleep -Seconds 1

# ---- Step 4: Force-delete all backups ----
Write-Host "[4/5] Force-deleting all backups in $BackupDir ..." -ForegroundColor Cyan
if (-not (Test-Path $BackupDir -EA SilentlyContinue)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    Write-Host "    Created $BackupDir (was missing)" -ForegroundColor Yellow
} else {
    $files = Get-ChildItem -Path $BackupDir -Recurse -Force -ErrorAction SilentlyContinue
    $count = $files.Count
    if ($count -eq 0) {
        Write-Host "    $BackupDir already empty." -ForegroundColor Green
    } else {
        # Primary: Remove-Item (works now that MIG is disabled)
        $files | Where-Object { -not $_.PSIsContainer } | Remove-Item -Force -EA SilentlyContinue
        # Fallback: cmd del for any stubborn files
        $remaining = Get-ChildItem -Path $BackupDir -Recurse -Force -ErrorAction SilentlyContinue |
                     Where-Object { -not $_.PSIsContainer }
        foreach ($item in $remaining) {
            cmd /c "del /f /q `"$($item.FullName)`"" 2>&1 | Out-Null
        }
        # Remove empty dirs
        Get-ChildItem -Path $BackupDir -Recurse -Directory -Force -EA SilentlyContinue |
            Sort-Object FullName -Descending |
            ForEach-Object { Remove-Item $_.FullName -Force -Recurse -EA SilentlyContinue }

        Start-Sleep -Seconds 1
        $stillLeft = Get-ChildItem -Path $BackupDir -Recurse -Force -ErrorAction SilentlyContinue
        if ($stillLeft) {
            Write-Host "    ERROR: $($stillLeft.Count) files could NOT be deleted:" -ForegroundColor Red
            $stillLeft | ForEach-Object { Write-Host "      $($_.FullName)" -ForegroundColor Red }
            exit 1
        } else {
            Write-Host "    SUCCESS: All $count items deleted. $BackupDir is empty." -ForegroundColor Green
        }
    }
}

# ---- Step 5: Restore guardian and restart service ----
Write-Host "[5/5] Restoring MIG (Enabled=$prevEnabled) and restarting MacriumService..." -ForegroundColor Cyan
Set-ItemProperty $migKey -Name 'Enabled' -Value ([int]$prevEnabled) -Type DWord -EA SilentlyContinue
Start-Service -Name 'MacriumService' -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2
Write-Host "    MacriumService: $((Get-Service 'MacriumService' -EA SilentlyContinue).Status)" -ForegroundColor Green
Write-Host "    MIG Enabled restored to: $prevEnabled" -ForegroundColor Green

Write-Host "`nCleanupBackups DONE. F:\win11recovery cleared and guardian restored." -ForegroundColor Green
