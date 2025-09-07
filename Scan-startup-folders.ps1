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
  Add-Content -Path $LogPath -Value $line -Encoding utf8
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

function To-ISO8601 { param($dt) if ($dt -and $dt -is [datetime] -and $dt.Year -gt 1900) { $dt.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') } else { $null } }
function New-NdjsonLine { param([hashtable]$Data) ($Data | ConvertTo-Json -Compress -Depth 7) }
function Write-NDJSONLines {
  param([string[]]$JsonLines,[string]$Path=$ARLog)
  $tmp = Join-Path $env:TEMP ("arlog_{0}.tmp" -f ([guid]::NewGuid().ToString("N")))
  $dir = Split-Path -Parent $Path
  if ($dir -and -not (Test-Path $dir)) { New-Item -Path $dir -ItemType Directory -Force | Out-Null }
  $payload = ($JsonLines -join [Environment]::NewLine) + [Environment]::NewLine
  Set-Content -Path $tmp -Value $payload -Encoding ascii -Force
  try { Move-Item -Path $tmp -Destination $Path -Force } catch { Move-Item -Path $tmp -Destination ($Path + '.new') -Force }
}

function Test-DigitalSignature {
  param([string]$FilePath)
  try {
    if (Test-Path $FilePath) {
      $sig = Get-AuthenticodeSignature -FilePath $FilePath -ErrorAction SilentlyContinue
      return $sig.Status -eq 'Valid'
    }
  } catch { return $false }
  return $false
}

Rotate-Log
$runStart = Get-Date
Write-Log "=== SCRIPT START : Scan Startup & Run Keys (host=$HostName) ==="

try {
  $Locations = @(
    @{ type="Folder";   path="$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup" },
    @{ type="Folder";   path="$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup" },
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
    if ($item.target -match "Users\\[^\\]+\\AppData|\\Temp\\") {
      $item.flagged_reasons += "User/AppData/Temp location"
      Write-Log "Flagged: $($item.path) -> AppData/Temp location" 'WARN'
    }
    if ($item.target -match "\.exe(\s|$)") {
      $exe = ($item.target -replace '["'']', '') -split '\s+' | Select-Object -First 1
      if ($exe -and -not (Test-DigitalSignature -FilePath $exe)) {
        $item.flagged_reasons += "Unsigned executable"
        Write-Log "Flagged: $($item.path) -> Unsigned executable ($exe)" 'WARN'
      }
    }
  }

  $tsNow = To-ISO8601 (Get-Date)
  $countAll = ($Items | Measure-Object).Count
  $flaggedOnly = $Items | Where-Object { $_.flagged_reasons.Count -gt 0 }
  $countFlagged = ($flaggedOnly | Measure-Object).Count

  if ($countAll -eq 0) {
    $nores = New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = "scan_startup_runkeys"
      copilot_action = $true
      item           = "status"
      status         = "no_results"
      description    = "No startup folder items or Run keys found"
    }
    Write-NDJSONLines -JsonLines @($nores) -Path $ARLog
    Write-Log "No items found; wrote status line to AR log" 'INFO'
    $dur = [int]((Get-Date) - $runStart).TotalSeconds
    Write-Log "=== SCRIPT END : duration ${dur}s ==="
    return
  }

  $lines = New-Object System.Collections.ArrayList
  [void]$lines.Add( (New-NdjsonLine @{
    timestamp      = $tsNow
    host           = $HostName
    action         = "scan_startup_runkeys"
    copilot_action = $true
    item           = "summary"
    description    = "Run summary and counts"
    item_count     = $countAll
    flagged_count  = $countFlagged
  }) )

  foreach ($it in $Items) {
    $desc = "Startup item at '$($it.path)'; flagged=" + ([bool]($it.flagged_reasons.Count -gt 0))
    [void]$lines.Add( (New-NdjsonLine @{
      timestamp      = $tsNow
      host           = $HostName
      action         = "scan_startup_runkeys"
      copilot_action = $true
      item           = "entry"
      description    = $desc
      location       = $it.location
      path           = $it.path
      target         = $it.target
      flagged        = ($it.flagged_reasons.Count -gt 0)
      reasons        = $it.flagged_reasons
    }) )
  }

  Write-NDJSONLines -JsonLines $lines -Path $ARLog
  Write-Log ("Wrote {0} NDJSON record(s) to {1}" -f $lines.Count, $ARLog) 'INFO'

  Write-Host "`n=== Startup & Run Key Scan Report ==="
  Write-Host "Host: $HostName"
  Write-Host "Total Items Found: $countAll"
  Write-Host "Flagged Items: $countFlagged"
  if ($countFlagged -gt 0) {
    $flaggedOnly | Select-Object location, path, target | Format-Table -AutoSize
  } else {
    Write-Host "No suspicious startup items detected."
  }
}
catch {
  Write-Log $_.Exception.Message 'ERROR'
  $err = New-NdjsonLine @{
    timestamp      = To-ISO8601 (Get-Date)
    host           = $HostName
    action         = "scan_startup_runkeys"
    copilot_action = $true
    item           = "error"
    description    = "Unhandled error"
    error          = $_.Exception.Message
  }
  Write-NDJSONLines -JsonLines @($err) -Path $ARLog
  Write-Log "Error NDJSON written to AR log" 'INFO'
}
finally {
  $dur = [int]((Get-Date) - $runStart).TotalSeconds
  Write-Log "=== SCRIPT END : duration ${dur}s ==="
}
