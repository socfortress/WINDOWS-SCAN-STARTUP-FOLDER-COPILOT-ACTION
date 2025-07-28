[CmdletBinding()]
param(
  [int]$MaxWaitSeconds = 300,
  [string]$LogPath = "$env:TEMP\Scan-Startup-Folders.log",
  [string]$ARLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
)

$ErrorActionPreference = 'Stop'
$HostName = $env:COMPUTERNAME
$LogMaxKB = 100
$LogKeep = 5

function Write-Log {
  param([string]$Message, [ValidateSet('INFO','WARN','ERROR','DEBUG')]$Level = 'INFO')
  $ts = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss.fff')
  $line = "[$ts][$Level] $Message"
  switch ($Level) {
    'ERROR' { Write-Host $line -ForegroundColor Red }
    'WARN'  { Write-Host $line -ForegroundColor Yellow }
    'DEBUG' { if ($PSCmdlet.MyInvocation.BoundParameters.ContainsKey('Verbose')) { Write-Verbose $line } }
    default { Write-Host $line }
  }
  Add-Content -Path $LogPath -Value $line
}

function Rotate-Log {
  if (Test-Path $LogPath -PathType Leaf) {
    if ((Get-Item $LogPath).Length / 1KB -gt $LogMaxKB) {
      for ($i = $LogKeep - 1; $i -ge 0; $i--) {
        $old = "$LogPath.$i"
        $new = "$LogPath." + ($i + 1)
        if (Test-Path $old) { Rename-Item $old $new -Force }
      }
      Rename-Item $LogPath "$LogPath.1" -Force
    }
  }
}

function Test-DigitalSignature {
  param([string]$FilePath)
  try {
    if (Test-Path $FilePath) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath
      return $sig.Status -eq 'Valid'
    }
  } catch { return $false }
  return $false
}

Rotate-Log

try {
  if (Test-Path $ARLog) {
    Remove-Item -Path $ARLog -Force -ErrorAction Stop
  }
  New-Item -Path $ARLog -ItemType File -Force | Out-Null
  Write-Log "Active response log cleared for fresh run."
} catch {
  Write-Log "Failed to clear ${ARLog}: $($_.Exception.Message)" 'WARN'
}

$runStart = Get-Date
Write-Log "=== SCRIPT START : Scan Startup & Run Keys ==="

try {
  $Locations = @(
    @{ type="Folder"; path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" },
    @{ type="Folder"; path="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" },
    @{ type="Registry"; path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" },
    @{ type="Registry"; path="HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" }
  )

  $Items = @()
  foreach ($loc in $Locations) {
    if ($loc.type -eq "Folder" -and (Test-Path $loc.path)) {
      Get-ChildItem $loc.path -ErrorAction SilentlyContinue | ForEach-Object {
        $Items += [PSCustomObject]@{
          location = "Startup Folder"
          path = $_.FullName
          target = $_.FullName
          flagged_reasons = @()
        }
      }
    } elseif ($loc.type -eq "Registry" -and (Test-Path $loc.path)) {
      $props = Get-ItemProperty $loc.path -ErrorAction SilentlyContinue
      $props.PSObject.Properties | Where-Object {
        $_.MemberType -eq 'NoteProperty' -and
        $_.Name -notmatch '^PS(ParentPath|ChildName|Path|Drive|Provider)$' -and
        $_.Value -is [string]
      } | ForEach-Object {
        $Items += [PSCustomObject]@{
          location = "Run Registry"
          path = "$($loc.path)\$($_.Name)"
          target = $_.Value
          flagged_reasons = @()
        }
      }
    }
  }

  foreach ($item in $Items) {
    if ($item.target -match "Users\\[^\\]+\\AppData") {
      $item.flagged_reasons += "User/AppData/Temp location"
      Write-Log "Flagged: $($item.path) -> AppData location" 'WARN'
    }
    if ($item.target -match "\.exe$") {
      $exe = ($item.target -replace '["''\s]', '') -split '\s' | Select-Object -First 1
      if ($exe -and -not (Test-DigitalSignature -FilePath $exe)) {
        $item.flagged_reasons += "Unsigned executable"
        Write-Log "Flagged: $($item.path) -> Unsigned executable ($exe)" 'WARN'
      }
    }
  }

  $timestamp = (Get-Date).ToString("o")
  $FullReport = [pscustomobject]@{
    host = $HostName
    timestamp = $timestamp
    action = "scan_startup_runkeys"
    item_count = $Items.Count
    items = $Items
    copilot_soar = $true
  }
  $FlaggedReport = [pscustomobject]@{
    host = $HostName
    timestamp = $timestamp
    action = "scan_startup_runkeys_flagged"
    flagged_count = ($Items | Where-Object { $_.flagged_reasons.Count -gt 0 }).Count
    flagged_items = $Items | Where-Object { $_.flagged_reasons.Count -gt 0 }
  }

  $FullReport | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
  $FlaggedReport | ConvertTo-Json -Depth 5 -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000

  Write-Log "JSON reports (full + flagged) written to $ARLog"
  Write-Host "`n=== Startup & Run Key Scan Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Items Found: $($Items.Count)"
  Write-Host "Flagged Items: $($FlaggedReport.flagged_count)"
  if ($FlaggedReport.flagged_count -gt 0) {
    $FlaggedReport.flagged_items | Select-Object location, path, target | Format-Table -AutoSize
  }
} catch {
  Write-Log $_.Exception.Message 'ERROR'
  $errorLog = [pscustomobject]@{
    timestamp = (Get-Date).ToString('o')
    host = $HostName
    action = "scan_startup_runkeys_error"
    status = "error"
    error = $_.Exception.Message
    copilot_soar = $true
  }
  $errorLog | ConvertTo-Json -Compress | Out-File -FilePath $ARLog -Append -Encoding ascii -Width 2000
} finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
