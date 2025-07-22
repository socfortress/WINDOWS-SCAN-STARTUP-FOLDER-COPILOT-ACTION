# PowerShell Scan Startup Folders & Run Keys Template

This repository provides a template for PowerShell-based active response scripts for security automation and incident response. The template ensures consistent logging, error handling, and execution flow for scanning Windows startup folders and registry run keys for persistence and suspicious entries.

---

## Overview

The `Scan-Startup-Folders.ps1` script inventories all startup folder items and registry run key entries on a Windows system, flags suspicious or risky entries (such as unsigned executables or those in user/AppData locations), and logs all actions, results, and errors in both a script log and an active-response log. This makes it suitable for integration with SOAR platforms, SIEMs, and incident response workflows.

---

## Template Structure

### Core Components

- **Parameter Definitions**: Configurable script parameters
- **Logging Framework**: Consistent logging with timestamps and rotation
- **Flagging Logic**: Identifies risky or suspicious startup/run entries
- **JSON Output**: Standardized response format
- **Execution Timing**: Performance monitoring

---

## How Scripts Are Invoked

### Command Line Execution

```powershell
.\Scan-Startup-Folders.ps1 [-MaxWaitSeconds <int>] [-LogPath <string>] [-ARLog <string>]
```

### Parameters

| Parameter        | Type   | Default Value                                                    | Description                                  |
|------------------|--------|------------------------------------------------------------------|----------------------------------------------|
| `MaxWaitSeconds` | int    | `300`                                                            | Maximum wait time for script execution       |
| `LogPath`        | string | `$env:TEMP\Scan-Startup-Folders.log`                             | Path for execution logs                      |
| `ARLog`          | string | `C:\Program Files (x86)\ossec-agent\active-response\active-responses.log` | Path for active response JSON output         |

---

### Example Invocations

```powershell
# Basic execution with default parameters
.\Scan-Startup-Folders.ps1

# Custom log path
.\Scan-Startup-Folders.ps1 -LogPath "C:\Logs\StartupScan.log"

# Integration with OSSEC/Wazuh active response
.\Scan-Startup-Folders.ps1 -ARLog "C:\ossec\active-responses.log"
```

---

## Template Functions

### `Write-Log`
**Purpose**: Standardized logging with severity levels and console output.

**Parameters**:
- `Message` (string): The log message
- `Level` (ValidateSet): Log level - 'INFO', 'WARN', 'ERROR', 'DEBUG'

**Features**:
- Timestamped output
- Color-coded console output
- File logging
- Verbose/debug support

**Usage**:
```powershell
Write-Log "Flagged: $($item.path) -> AppData location" 'WARN'
Write-Log "Flagged: $($item.path) -> Unsigned executable ($exe)" 'WARN'
Write-Log "JSON reports (full + flagged) appended to $ARLog" 'INFO'
```

---

### `Rotate-Log`
**Purpose**: Manages log file size and rotation.

**Features**:
- Monitors log file size (default: 100KB)
- Maintains a configurable number of backups (default: 5)
- Rotates logs automatically

**Configuration Variables**:
- `$LogMaxKB`: Max log file size in KB
- `$LogKeep`: Number of rotated logs to retain

---

### `Test-DigitalSignature`
**Purpose**: Checks if a file (such as a startup executable) is digitally signed.

**Parameters**:
- `FilePath` (string): Path to the executable

**Features**:
- Returns `$true` if the file is signed and valid, `$false` otherwise

---

## Script Execution Flow

1. **Initialization**
   - Parameter validation and assignment
   - Error action preference
   - Log rotation
   - Start time logging

2. **Execution**
   - Enumerates startup folders and registry run keys
   - Flags items based on:
     - User/AppData/Temp location
     - Unsigned executables
   - Logs findings

3. **Completion**
   - Outputs full inventory and flagged items as JSON to the active response log
   - Logs script end and duration
   - Displays summary in console

4. **Error Handling**
   - Catches and logs exceptions
   - Outputs error details as JSON

---

## JSON Output Format

### Full Report Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "scan_startup_runkeys",
  "item_count": 12,
  "items": [
    {
      "location": "Startup Folder",
      "path": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.lnk",
      "target": "C:\\Users\\user\\AppData\\malware.exe",
      "flagged_reasons": ["User/AppData/Temp location", "Unsigned executable"]
    }
  ]
}
```

### Flagged Items Example

```json
{
  "host": "HOSTNAME",
  "timestamp": "2025-07-22T10:30:45.123Z",
  "action": "scan_startup_runkeys_flagged",
  "flagged_count": 1,
  "flagged_items": [
    {
      "location": "Startup Folder",
      "path": "C:\\Users\\user\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\malware.lnk",
      "target": "C:\\Users\\user\\AppData\\malware.exe",
      "flagged_reasons": ["User/AppData/Temp location", "Unsigned executable"]
    }
  ]
}
```

### Error Example

```json
{
  "timestamp": "2025-07-22T10:31:10.456Z",
  "host": "HOSTNAME",
  "action": "scan_startup_runkeys_error",
  "status": "error",
  "error": "Access is denied"
}
```

---

## Implementation Guidelines

1. Use the provided logging and error handling functions.
2. Customize the flagging logic as needed for your environment.
3. Ensure JSON output matches your SOAR/SIEM requirements.
4. Test thoroughly in a non-production environment.

---

## Security Considerations

- Run with the minimum required privileges.
- Validate all input parameters.
- Secure log files and output locations.
- Monitor for errors and failed inventory.

---

## Troubleshooting

- **Permission Errors**: Run as Administrator.
- **Registry/Folder Access Issues**: Ensure the script has access to all startup folders and registry hives.
- **Log Output**: Check file permissions and disk space.

---

## License

This template is provided as-is for security automation
