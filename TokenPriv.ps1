function Enable-TokenPrivilege {
    <#
    .SYNOPSIS
        Enables a specified privilege for the current PowerShell process.
    .PARAMETER Privilege
        The privilege name (e.g., 'SeDebugPrivilege', 'SeRestorePrivilege', 'SeTakeOwnershipPrivilege').
    .EXAMPLE
        Enable-TokenPrivilege SeDebugPrivilege
    .EXAMPLE
        Enable-TokenPrivilege SeRestorePrivilege
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, Position=0)]
        [string]$Privilege
    )

    # Add the required interop types (will not re-add if already present)
    Add-Type -TypeDefinition @"
using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

[StructLayout(LayoutKind.Sequential, Pack = 1)]
public struct TokPriv1Luid {
    public int Count;
    public long Luid;
    public int Attr;
}
public static class Advapi32 {
    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool OpenProcessToken(
        IntPtr ProcessHandle,
        int DesiredAccess,
        ref IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError=true)]
    public static extern bool LookupPrivilegeValue(
        string lpSystemName,
        string lpName,
        ref long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(
        IntPtr TokenHandle,
        bool DisableAllPrivileges,
        ref TokPriv1Luid NewState,
        int BufferLength,
        IntPtr PreviousState,
        IntPtr ReturnLength);
}
public static class Kernel32 {
    [DllImport("kernel32.dll")]
    public static extern uint GetLastError();
}
"@ -ErrorAction SilentlyContinue

    # Get the current process handle (reliable in PowerShell)
    $ProcHandle = (Get-Process -Id $PID).Handle

    # Open the process token
    $hTokenHandle = [IntPtr]::Zero
    $CallResult = [Advapi32]::OpenProcessToken($ProcHandle, 0x28, [ref]$hTokenHandle)
    if (-not $CallResult) {
        Write-Error "Failed to open process token. Try running as Administrator."
        return
    }

    # Prepare the privilege structure
    $TokPriv1Luid = New-Object TokPriv1Luid
    $TokPriv1Luid.Count = 1
    $TokPriv1Luid.Attr = 0x00000002 # SE_PRIVILEGE_ENABLED

    # Lookup the LUID for the specified privilege
    $LuidVal = $null
    $CallResult = [Advapi32]::LookupPrivilegeValue($null, $Privilege, [ref]$LuidVal)
    if (-not $CallResult) {
        Write-Error "Failed to lookup LUID for '$Privilege'."
        return
    }
    $TokPriv1Luid.Luid = $LuidVal

    # Enable the privilege
    $CallResult = [Advapi32]::AdjustTokenPrivileges($hTokenHandle, $false, [ref]$TokPriv1Luid, 0, [IntPtr]::Zero, [IntPtr]::Zero)
    $LastError = [Kernel32]::GetLastError()
    if ($CallResult -and $LastError -eq 0) {
        Write-Host "Privilege '$Privilege' enabled for this process." -ForegroundColor Green
    } elseif ($LastError -eq 1300) {
        Write-Warning "Privilege '$Privilege' is not present in your token (check whoami /priv)."
    } else {
        Write-Host "Failed to enable '$Privilege'. Error: $LastError" -ForegroundColor Red
    }

    # Show updated privilege state
    Write-Host "`nCurrent privileges for process $PID (`whoami /priv`):"
    whoami /priv
}

# --- Example Usage ---
# Enable-TokenPrivilege SeRestorePrivilege
# Enable-TokenPrivilege SeDebugPrivilege
