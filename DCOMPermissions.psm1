<#

VERSION      DATE          AUTHOR
1.0.09       2017-09-15    Tony Pombo
    - Initial Release

1.1.03       2017-09-22    Tony Pombo
    - Replaced localized English names with SIDs
    - Minor code cleanup

#> # Revision History

#Requires -Version 4.0
Set-StrictMode -Version 2.0

$ACL_REVISION = 2
$COM_RIGHTS_EXECUTE = 1
$COM_RIGHTS_EXECUTE_LOCAL = 2
$COM_RIGHTS_EXECUTE_REMOTE = 4
$COM_RIGHTS_ACTIVATE_LOCAL = 8
$COM_RIGHTS_ACTIVATE_REMOTE = 16

$Admins_SID = [System.Security.Principal.SecurityIdentifier]"S-1-5-32-544"
$System_SID = [System.Security.Principal.SecurityIdentifier]"S-1-5-18"

# The code for: Add-Type, Grant-TokenPrivilege, Revoke-TokenPrivilege
#   is a subset of the "Grant, Revoke, Query user rights (privileges) using PowerShell" v1.3.1
#   script available at https://gallery.technet.microsoft.com/Grant-Revoke-Query-user-26e259b0

Add-Type @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
'@ # This type is used by Grant-TokenPriviledge, Revoke-TokenPrivilege

function Grant-TokenPrivilege {
 <#
  .SYNOPSIS
    Enables privileges in the current process token.
  .DESCRIPTION
    Enables one or more privileges for the current process token. If a privilege cannot be enabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to enable. More than one privilege may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Grant-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Enables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege) {
            try { [PS_LSA.TokenManipulator]::AddPrivilege($Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
            }
        }
    }
} # Enables privileges in the current process token

function Revoke-TokenPrivilege {
 <#
  .SYNOPSIS
    Disables privileges in the current process token.
  .DESCRIPTION
    Disables one or more privileges for the current process token. If a privilege cannot be disabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to disable. More than one privilege may be listed.

    Possible values: 
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Revoke-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Disables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege) {
            try { [PS_LSA.TokenManipulator]::RemovePrivilege($Priv) }
            catch [System.ComponentModel.Win32Exception] {
                throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
            }
        }
    }
} # Disables privileges in the current process token

function Get-DComPermission {
 <#
  .SYNOPSIS
    Gets DCOM Permissions for a specified Application ID

  .DESCRIPTION
    Retrieves either the "Access Permissions" or "Launch and Activation Permissions" for a specified Application ID

  .PARAMETER ApplicationID
    The Application ID for the DCOM object

  .PARAMETER Type
    Indicates which type of permissions to retrieve
    Valid options:  Launch, Access

  .EXAMPLE
    Get-DCOMPermission -ApplicationID "{9CA88EE3-ACB7-47C8-AFC4-AB702511C276}" -Type Launch

  .INPUTS
    String ApplicationID
    String Type

  .OUTPUTS
    String ApplicationID
    String Type
    String[] Access
    Int AccessMask
    System.Security.Principal.SecurityIdentifier SID
    String Name
 #>
    param(
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias("APPID")] [string[]] $ApplicationID,

        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet("Launch","Access")] [string] $Type
    )

    begin {
        $ErrorActionPreference = "Stop"
        New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -Scope Local -ErrorAction SilentlyContinue | Out-Null
    }
    process {
        foreach ($APPID in $ApplicationID) {
        Write-Verbose "Getting registry value HKCR:\AppID\$APPID\$($Type)Permission"
        $regkey = Get-Item -Path "HKCR:\AppID\$APPID"

        try {
            $reg_perms = ($regkey | Get-ItemProperty -Name "$($Type)Permission")."$($Type)Permission"
        } catch {
            if ($_.Exception.Message -match "Property $($Type)Permission does not exist") {
                return "Default $Type permissions are inherited for $APPID"
            } else {throw $_ }
        }

        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($reg_perms, 0)

        foreach ($ace in $sd.DiscretionaryAcl) {
            Write-Verbose "Working on $($ace.SecurityIdentifier)"
            try { $User = (($ace.SecurityIdentifier).Translate([System.Security.Principal.NTAccount])).Value }
            catch { Write-Warning "Unable to map SID to name. $($ace.SecurityIdentifier)" ; $User=$null }
        
            $access = @()

            if ($Type -eq "Launch") {
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL) -or 
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and 
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "LocalLaunch" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "RemoteLaunch" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_ACTIVATE_LOCAL) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_REMOTE))) ) { $access += "LocalActivation" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_ACTIVATE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band ($COM_RIGHTS_EXECUTE_LOCAL -bor
                                                 $COM_RIGHTS_EXECUTE_REMOTE -bor
                                                 $COM_RIGHTS_ACTIVATE_LOCAL))) ) { $access += "RemoteActivation" }
            } else {
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE)) ) { $access += "LocalAccess" }
                if ( ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE) -or
                    (($ace.AccessMask -band $COM_RIGHTS_EXECUTE) -and
                    -not ($ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL)) ) { $access += "RemoteAccess" }
            }

            New-Object -TypeName PSObject -Property @{
                "ApplicationID" = $APPID
                "Type" = $ace.AceType ;
                "Access" = $access ;
                "AccessMask" = $ace.AccessMask ;
                "SID" = $ace.SecurityIdentifier ;
                "Name" = $User
            }
        }
    }
    }
}

function Grant-DComPermissionInternal {
    param(
        [string]  $ApplicationID,
        [string]  $Type,
        [System.Security.Principal.SecurityIdentifier] $SID,
        [string[]] $Permissions,
        [System.Security.AccessControl.AceType] $AceType,
        [Switch]  $PassThru
    )

    New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -Scope Local -ErrorAction SilentlyContinue | Out-Null

    Write-Verbose "Getting registry value responsible for COM security"
    $regkey = Get-Item -Path "HKCR:\AppID\$ApplicationID"

    try {
        $reg_perms = ($regkey | Get-ItemProperty -Name "$($Type)Permission")."$($Type)Permission"
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($reg_perms, 0)
    } catch {
        Write-Verbose "Replacing default permissions with new security descriptor"
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor(
                ([System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent -bor
                [System.Security.AccessControl.ControlFlags]::SelfRelative),
                $System_SID, $System_SID, $null,
                $(New-Object System.Security.AccessControl.RawAcl($ACL_REVISION,1)) )
    }

    Write-Verbose "Determining new ACE properties"
    $AccessMask = $COM_RIGHTS_EXECUTE
    if ($Permissions -contains "ALL") {
        if ($Type -eq "Launch") { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_LOCAL -bor $COM_RIGHTS_EXECUTE_REMOTE -bor $COM_RIGHTS_ACTIVATE_LOCAL -bor $COM_RIGHTS_ACTIVATE_REMOTE }
        else { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_LOCAL -bor $COM_RIGHTS_EXECUTE_REMOTE }
    } else {
        if ($Permissions -contains "LocalLaunch") { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_LOCAL }
        if ($Permissions -contains "RemoteLaunch") { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_REMOTE }
        if ($Permissions -contains "LocalActivation") { $AccessMask = $AccessMask -bor $COM_RIGHTS_ACTIVATE_LOCAL }
        if ($Permissions -contains "RemoteActivation") { $AccessMask = $AccessMask -bor $COM_RIGHTS_ACTIVATE_REMOTE }
        if ($Permissions -contains "LocalAccess") { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_LOCAL }
        if ($Permissions -contains "RemoteAccess") { $AccessMask = $AccessMask -bor $COM_RIGHTS_EXECUTE_REMOTE }
    }
   
    Write-Verbose "Searching for existing ACE for this user"
    $acl = $sd.DiscretionaryAcl
    $found = $false

    foreach ($ace in $acl) {
        if ($ace.SecurityIdentifier -eq $SID -and $ace.AceType -eq $AceType) {
            $ace.AccessMask = $ace.AccessMask -bor $AccessMask
            $found = $true
            break
        }
    }

    if (-not $found) {
        Write-Verbose "Not found, creating new ACE entry"
        $ace = New-Object System.Security.AccessControl.CommonAce(
            [System.Security.AccessControl.AceFlags]::None,
            [System.Security.AccessControl.AceQualifier]$AceType.value__,
            $AccessMask, $SID, $false, $null)
    
        if ($AceType -match "denied") { $acl.InsertAce(0, $ace) }
        else { $acl.InsertAce($acl.Count, $ace) }
    }

    Write-Verbose "Convert to binary and save the ACL"
    $sd.DiscretionaryAcl = $acl
    $sdbytes = New-Object 'byte[]' $sd.BinaryLength 
    $sd.GetBinaryForm($sdbytes, 0) 
    $regkey | New-ItemProperty -Name "$($Type)Permission" -PropertyType Binary -Value $sdBytes -Force | Out-Null

    if ($PassThru) { New-Object -TypeName PSObject -Property @{ "ApplicationID" = $ApplicationID ; "Type" = $Type } }
}

function Revoke-DComPermissionInternal {
    param(
        [string]  $ApplicationID,
        [string]  $Type,
        [System.Security.Principal.SecurityIdentifier] $SID,
        [string[]] $Permissions,
        [System.Security.AccessControl.AceType] $AceType,
        [Switch]  $PassThru
    )

    New-PSDrive -PSProvider Registry -Root HKEY_CLASSES_ROOT -Name HKCR -Scope Local -ErrorAction SilentlyContinue | Out-Null

    Write-Verbose "Getting registry value responsible for COM security"
    $regkey = Get-Item -Path "HKCR:\AppID\$ApplicationID"

    try {
        $reg_perms = ($regkey | Get-ItemProperty -Name "$($Type)Permission")."$($Type)Permission"
        $sd = New-Object System.Security.AccessControl.RawSecurityDescriptor($reg_perms, 0)
    } catch { Write-Warning "Using default permissions (no changes made)" ; return }

    Write-Verbose "Searching for existing ACE for this user"
    $acl = $sd.DiscretionaryAcl
    $found = $false

    for ($index=0 ; $index -lt $acl.Count; $index++) {
        $ace = $acl[$index]
        if ($ace.SecurityIdentifier -eq $SID -and $ace.AceType -eq $AceType) {
            Write-Verbose "Found ACE for this user"

            if ($Permissions -contains "LocalLaunch" -and $ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_EXECUTE_LOCAL }
            if ($Permissions -contains "RemoteLaunch" -and $ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_EXECUTE_REMOTE }
            if ($Permissions -contains "LocalActivation" -and $ace.AccessMask -band $COM_RIGHTS_ACTIVATE_LOCAL)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_ACTIVATE_LOCAL }
            if ($Permissions -contains "RemoteActivation" -and $ace.AccessMask -band $COM_RIGHTS_ACTIVATE_REMOTE)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_ACTIVATE_REMOTE }
            if ($Permissions -contains "LocalAccess" -and $ace.AccessMask -band $COM_RIGHTS_EXECUTE_LOCAL)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_EXECUTE_LOCAL }
            if ($Permissions -contains "RemoteAccess" -and $ace.AccessMask -band $COM_RIGHTS_EXECUTE_REMOTE)
                { $ace.AccessMask = $ace.AccessMask -bxor $COM_RIGHTS_EXECUTE_REMOTE }

            if ($Permissions -contains "ALL" -or $ace.AccessMask -eq 0 -or $ace.AccessMask -eq $COM_RIGHTS_EXECUTE)
                { $acl.RemoveAce($index) }

            $found = $true
            break
        }
    }

    if (-not $found) { Write-Verbose "ACE not found, no changes made" }
    else {
        Write-Verbose "Convert to binary and save the ACL"
        $sd.DiscretionaryAcl = $acl
        $sdbytes = New-Object 'byte[]' $sd.BinaryLength 
        $sd.GetBinaryForm($sdbytes, 0) 
        $regkey | New-ItemProperty -Name "$($Type)Permission" -PropertyType Binary -Value $sdBytes -Force | Out-Null
    }

    if ($PassThru) { New-Object -TypeName PSObject -Property @{ "ApplicationID" = $ApplicationID ; "Type" = $Type } }
}

function Wrapper-DComPermission {
    param(
        [Parameter(Mandatory=$true)] [ValidateSet("Grant","Revoke")] [string] $Purpose,
        [string]  $ApplicationID,
        [string]  $Type,
        [string]  $Account,
        [string[]] $Permissions,
        [Switch]  $Deny,
        [Switch]  $PassThru,
        [Switch]  $OverrideConfigurationPermissions
    )

    if ($Type -eq "Launch") {
        if ($Permissions -contains "LocalAccess") { throw New-Object System.ArgumentException("LocalAccess is not a valid Launch permission") }
        if ($Permissions -contains "RemoteAccess") { throw New-Object System.ArgumentException("RemoteAccess is not a valid Launch permission") }
    } else {
        if ($Permissions -contains "LocalLaunch") { throw New-Object System.ArgumentException("LocalLaunch is not a valid Access permission") }
        if ($Permissions -contains "RemoteLaunch") { throw New-Object System.ArgumentException("RemoteLaunch is not a valid Access permission") }
        if ($Permissions -contains "LocalActivation") { throw New-Object System.ArgumentException("LocalActivation is not a valid Access permission") }
        if ($Permissions -contains "RemoteActivation") { throw New-Object System.ArgumentException("RemoteActivation is not a valid Access permission") }
    }

    $AceType = [System.Security.AccessControl.AceType]::AccessAllowed
    if ($Deny) { $AceType = [System.Security.AccessControl.AceType]::AccessDenied }

    Write-Verbose "Getting SID from account name"
    $UserNTAccount = New-Object System.Security.Principal.NTAccount($Account)
    [System.Security.Principal.SecurityIdentifier] $SID = ($UserNTAccount.Translate([System.Security.Principal.SecurityIdentifier])).Value

    try {
        if ($Purpose -eq "Grant") { Grant-DComPermissionInternal -ApplicationID $ApplicationID -SID $SID -Type $Type -Permissions $Permissions -AceType $AceType -PassThru:$PassThru }
        else { Revoke-DComPermissionInternal -ApplicationID $ApplicationID -SID $SID -Type $Type -Permissions $Permissions -AceType $AceType -PassThru:$PassThru }
    } catch [System.Security.SecurityException] {
        Write-Verbose "Access denied setting DCOM permissions (registry configuration permissions are lacking...)"
        if (-not $OverrideConfigurationPermissions) { Write-Verbose "...Override not specified, aborting" ; throw $_ }
        else { Write-Verbose "...Attempting to override" }
           
        if (-not [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544"))
            { Write-Warning "No administrator rights (not elevated)" ; throw $_ }

        $OldOwner = $null
        $RevokePrivilege = $false

        # User has admin rights, but Admininstrators do not have rights to change values. Need to change permissions
        Write-Verbose "Opening registry key to change its permissions"
        try {
            $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\$ApplicationID", 'ReadWriteSubTree', 'ChangePermissions')
        } catch [System.Security.SecurityException] {
            Write-Verbose "Access denied opening registry key to change permissions (not owner)`n`tReopening registry key to take ownership"
            try {
                $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\$ApplicationID", 'ReadWriteSubTree', 'TakeOwnership')
            } catch [System.Security.SecurityException] {
                Write-Verbose "Access denied opening registry key to take ownership, enabling Token Privileges and trying again"
                Grant-TokenPrivilege -Privilege SeTakeOwnershipPrivilege,SeRestorePrivilege
                $RevokePrivilege = $true
                $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\$ApplicationID", 'ReadWriteSubTree', 'TakeOwnership')
            }

            Write-Verbose "Setting owner to Administrators"
            try {
                $acl = $key.GetAccessControl()
                $OldOwner = [System.Security.Principal.NTAccount]$acl.Owner
                $acl.SetOwner($Admins_SID)
                $key.SetAccessControl($acl)
            } catch {
                if ($RevokePrivilege) { try { Revoke-TokenPrivilege -Privilege SeTakeOwnershipPrivilege,SeRestorePrivilege } catch {} }
                throw $_
            } finally {
                $key.Close()
            }

            Write-Verbose "Retry: opening registry key to change its permissions"
            try {
                $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\$ApplicationID", 'ReadWriteSubTree', 'ChangePermissions')
            } catch {
                Write-Verbose "Failed again (you should never see this). Restoring original owner"
                $key = [Microsoft.Win32.Registry]::ClassesRoot.OpenSubKey("AppID\$ApplicationID", 'ReadWriteSubTree', 'TakeOwnership')
                $acl = $key.GetAccessControl()
                $acl.SetOwner($OldOwner)
                $key.SetAccessControl($acl)
                $key.Close()
                if ($RevokePrivilege) { try { Revoke-TokenPrivilege -Privilege SeTakeOwnershipPrivilege,SeRestorePrivilege } catch {} }
                throw $_
            }
        }

        Write-Verbose "Setting ACL to grant Administrators full control"
        $acl = $key.GetAccessControl()
        $acl_original = $key.GetAccessControl()
        $acl_original.SetAccessRuleProtection($acl_original.AreAccessRulesProtected, $true) # Must "change" ACL, or .NET won't save it
        $rule = New-Object System.Security.AccessControl.RegistryAccessRule($Admins_SID, "FullControl", "ContainerInherit", "None", "Allow")
        $acl.ResetAccessRule($rule) # Replace all ACEs for Administrators with one that grants full control
        $key.SetAccessControl($acl)

        try {
            if ($Purpose -eq "Grant") { Grant-DComPermissionInternal -ApplicationID $ApplicationID -SID $SID -Type $Type -Permissions $Permissions -AceType $AceType -PassThru:$PassThru }
            else { Revoke-DComPermissionInternal -ApplicationID $ApplicationID -SID $SID -Type $Type -Permissions $Permissions -AceType $AceType -PassThru:$PassThru }
        } catch {
            throw $_
        } finally {
            # Set ACL back to original value
            Write-Verbose "Restoring original registry key permissions & owner"
            if ($OldOwner) { $acl_original.SetOwner($OldOwner) }
            $key.SetAccessControl($acl_original)
            $key.Close()

            if ($RevokePrivilege) { try { Revoke-TokenPrivilege -Privilege SeTakeOwnershipPrivilege,SeRestorePrivilege } catch {} }
        }
    }
}

function Grant-DComPermission {
 <#
  .SYNOPSIS
    Grants DCOM Permissions to a specified Application ID's Launch/Activation, or Access permissions

  .DESCRIPTION
    Grants individual "Access Permissions" or "Launch and Activation Permissions" to a specified Application ID for a specific account

  .PARAMETER ApplicationID
    The Application ID for the DCOM object

  .PARAMETER Type
    Indicates which type of permissions to grant
    Valid options:  Launch, Access

  .PARAMETER Account
    Account in the form of "Domain\Username".  Specify only the username for local accounts.

  .PARAMETER Permissions
    List of permissions to grant
    Valid options for Launch:  ALL, LocalLaunch, LocalActivation, RemoteLaunch, RemoteActivation
    Valid options for Access:  ALL, LocalAccess, RemoteAccess

  .PARAMETER Deny
    Create a DENY access control entry instead of an ALLOW entry

  .PARAMETER PassThru
    Outputs the ApplicationID and Type parameters.  This is useful for piping to Get-DCOMPermission.
    If not specified, nothing is outputted.

  .PARAMETER OverrideConfigurationPermissions
    For some DCOM objects (such as RuntimeBroker), Administrators do not have the needed "Configuration Permissions" to change the Launch or Access permissions.
    In these cases, an access denied error is generated. To avoid this error, specify this option.
    
    If this option is enabled and an access denied error occurs, then the "Configuration Permissions" will be temporarily changed (taking ownership as needed) to allow the DCOM permission change to succeed. Once complete, the configuration permissions and ownership are restored to the original values.

  .EXAMPLE
    Grant-DCOMPermission -ApplicationID "{9CA88EE3-ACB7-47C8-AFC4-AB702511C276}" -Account "SYSTEM" -Type Launch -Permissions LocalLaunch,LocalActivation

  .INPUTS
    String ApplicationID
    String Type
    String Account
    String[] Permissions
    Switch Deny
    Switch PassThru
    Switch OverrideConfigurationPermissions

  .OUTPUTS
    String ApplicationID
    String Type
 #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)] [Alias("APPID")] [string] $ApplicationID,
        [Parameter(Mandatory=$true)] [ValidateSet("Launch","Access")] [string] $Type,
        [Parameter(Mandatory=$true)] [Alias('Acct','User','Username')] [string] $Account,
        [Parameter(Mandatory=$true)] [ValidateSet("LocalLaunch","RemoteLaunch","LocalActivation",
                    "RemoteActivation","LocalAccess","RemoteAccess","ALL")] [string[]] $Permissions,
        [Switch] $Deny,
        [Switch] $PassThru,
        [Alias("Override")] [Switch] $OverrideConfigurationPermissions
    )

    $ErrorActionPreference = "Stop"
    Wrapper-DComPermission -Purpose Grant -ApplicationID $ApplicationID -Account $Account -Type $Type -Permissions $Permissions -Deny:$Deny -PassThru:$PassThru -OverrideConfigurationPermissions:$OverrideConfigurationPermissions
}

function Revoke-DComPermission {
 <#
  .SYNOPSIS
    Revokes DCOM Permissions from a specified Application ID's Launch/Activation, or Access permissions

  .DESCRIPTION
    Removes individual "Access Permissions" or "Launch and Activation Permissions" form a specified Application ID for a specific account

  .PARAMETER ApplicationID
    The Application ID for the DCOM object

  .PARAMETER Type
    Indicates which type of permissions to revoke
    Valid options:  Launch, Access

  .PARAMETER Account
    Account in the form of "Domain\Username".  Specify only the username for local accounts.

  .PARAMETER Permissions
    List of permissions to revoke
    Valid options for Launch:  ALL, LocalLaunch, LocalActivation, RemoteLaunch, RemoteActivation
    Valid options for Access:  ALL, LocalAccess, RemoteAccess

  .PARAMETER Deny
    Revoke a DENY access control entry instead of an ALLOW entry

  .PARAMETER PassThru
    Outputs the ApplicationID and Type parameters.  This is useful for piping to Get-DCOMPermission.
    If not specified, nothing is outputted.

  .PARAMETER OverrideConfigurationPermissions
    For some DCOM objects (such as RuntimeBroker), Administrators do not have the needed "Configuration Permissions" to change the Launch or Access permissions.
    In these cases, an access denied error is generated. To avoid this error, specify this option.
    
    If this option is enabled and an access denied error occurs, then the "Configuration Permissions" will be temporarily changed (taking ownership as needed) to allow the DCOM permission change to succeed. Once complete, the configuration permissions and ownership are restored to the original values.

  .EXAMPLE
    Revoke-DCOMPermission -ApplicationID "{9CA88EE3-ACB7-47C8-AFC4-AB702511C276}" -Account "SYSTEM" -Type Launch -Permissions LocalLaunch,LocalActivation

  .INPUTS
    String ApplicationID
    String Type
    String Account
    String[] Permissions
    Switch Deny
    Switch PassThru
    Switch OverrideConfigurationPermissions

  .OUTPUTS
    String ApplicationID
    String Type
 #>
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)] [Alias("APPID")] [string] $ApplicationID,
        [Parameter(Mandatory=$true)] [ValidateSet("Launch","Access")] [string] $Type,
        [Parameter(Mandatory=$true)] [Alias('Acct','User','Username')] [string] $Account,
        [Parameter(Mandatory=$true)] [ValidateSet("LocalLaunch","RemoteLaunch","LocalActivation",
                    "RemoteActivation","LocalAccess","RemoteAccess","ALL")] [string[]] $Permissions,
        [Switch] $Deny,
        [Switch] $PassThru,
        [Alias("Override")] [Switch] $OverrideConfigurationPermissions
    )

    $ErrorActionPreference = "Stop"
    Wrapper-DComPermission -Purpose Revoke -ApplicationID $ApplicationID -Account $Account -Type $Type -Permissions $Permissions -Deny:$Deny -PassThru:$PassThru -OverrideConfigurationPermissions:$OverrideConfigurationPermissions
}

Export-ModuleMember -Function Get-DComPermission, Grant-DComPermission, Revoke-DComPermission

# SIG # Begin signature block
# MIIcxAYJKoZIhvcNAQcCoIIctTCCHLECAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUF+g3EqM6uew2jE1X/qJvXbWA
# myagghfzMIIFMDCCBBigAwIBAgIQBAkYG1/Vu2Z1U0O1b5VQCDANBgkqhkiG9w0B
# AQsFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMTMxMDIyMTIwMDAwWhcNMjgxMDIyMTIwMDAwWjByMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQg
# Q29kZSBTaWduaW5nIENBMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
# +NOzHH8OEa9ndwfTCzFJGc/Q+0WZsTrbRPV/5aid2zLXcep2nQUut4/6kkPApfmJ
# 1DcZ17aq8JyGpdglrA55KDp+6dFn08b7KSfH03sjlOSRI5aQd4L5oYQjZhJUM1B0
# sSgmuyRpwsJS8hRniolF1C2ho+mILCCVrhxKhwjfDPXiTWAYvqrEsq5wMWYzcT6s
# cKKrzn/pfMuSoeU7MRzP6vIK5Fe7SrXpdOYr/mzLfnQ5Ng2Q7+S1TqSp6moKq4Tz
# rGdOtcT3jNEgJSPrCGQ+UpbB8g8S9MWOD8Gi6CxR93O8vYWxYoNzQYIH5DiLanMg
# 0A9kczyen6Yzqf0Z3yWT0QIDAQABo4IBzTCCAckwEgYDVR0TAQH/BAgwBgEB/wIB
# ADAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYBBQUHAwMweQYIKwYBBQUH
# AQEEbTBrMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wQwYI
# KwYBBQUHMAKGN2h0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFz
# c3VyZWRJRFJvb3RDQS5jcnQwgYEGA1UdHwR6MHgwOqA4oDaGNGh0dHA6Ly9jcmw0
# LmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwOqA4oDaG
# NGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RD
# QS5jcmwwTwYDVR0gBEgwRjA4BgpghkgBhv1sAAIEMCowKAYIKwYBBQUHAgEWHGh0
# dHBzOi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwCgYIYIZIAYb9bAMwHQYDVR0OBBYE
# FFrEuXsqCqOl6nEDwGD5LfZldQ5YMB8GA1UdIwQYMBaAFEXroq/0ksuCMS1Ri6en
# IZ3zbcgPMA0GCSqGSIb3DQEBCwUAA4IBAQA+7A1aJLPzItEVyCx8JSl2qB1dHC06
# GsTvMGHXfgtg/cM9D8Svi/3vKt8gVTew4fbRknUPUbRupY5a4l4kgU4QpO4/cY5j
# DhNLrddfRHnzNhQGivecRk5c/5CxGwcOkRX7uq+1UcKNJK4kxscnKqEpKBo6cSgC
# PC6Ro8AlEeKcFEehemhor5unXCBc2XGxDI+7qPjFEmifz0DLQESlE/DmZAwlCEIy
# sjaKJAL+L3J+HNdJRZboWR3p+nRka7LrZkPas7CM1ekN3fYBIM6ZMWM9CBoYs4Gb
# T8aTEAb8B4H6i9r5gkn3Ym6hU/oSlBiFLpKR6mhsRDKyZqHnGKSaZFHvMIIFfDCC
# BGSgAwIBAgIQAarMGW1/STo93o1TEWGeDjANBgkqhkiG9w0BAQsFADByMQswCQYD
# VQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGln
# aWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEyIEFzc3VyZWQgSUQgQ29k
# ZSBTaWduaW5nIENBMB4XDTE2MDgyMzAwMDAwMFoXDTE5MTEyMTEyMDAwMFowgbgx
# CzAJBgNVBAYTAlVTMQ0wCwYDVQQIEwRPaGlvMRQwEgYDVQQHEwtCZWF2ZXJjcmVl
# azEcMBoGA1UEChMTRWRpY3QgU3lzdGVtcywgSW5jLjEcMBoGA1UECxMTRWRpY3Qg
# U3lzdGVtcywgSW5jLjEcMBoGA1UEAxMTRWRpY3QgU3lzdGVtcywgSW5jLjEqMCgG
# CSqGSIb3DQEJARYbc2VydmVydGVhbUBlZGljdHN5c3RlbXMuY29tMIIBIjANBgkq
# hkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArIiBNxH+fwhHOImuhnPB8KkW7W2YOjs0
# jUPmBMCOz3tEGw+f3pxFY3excm6i2dpitj86tmtGkdg3eQFW83q0uRgSA8VYPyE5
# OiKoTwfJpt4RYbpcDXf7o7t/gwMEWh08A7I9bVyU4qtsUv5PF6SrdD4u7d16MxYm
# 4M4qjLv+u9sI7/urfzxQhbzGhGEuqMJGkNyYGX3QYMXq+nZThAA1u2NNkJNzzSh5
# fcsiPv8utB4r4pIgtL64eUIuYkx+j2n3BI/6yNxKCLb6Uu8/aSjS7I8MVFwJAFAr
# ueEflGCPi2Ab6CVwOrllEmxYVVqzPtXd+w376wxtc6cwZGcOqoWOzwIDAQABo4IB
# xTCCAcEwHwYDVR0jBBgwFoAUWsS5eyoKo6XqcQPAYPkt9mV1DlgwHQYDVR0OBBYE
# FArHIjPvp9Tepl+BpM6rruu3OF9rMA4GA1UdDwEB/wQEAwIHgDATBgNVHSUEDDAK
# BggrBgEFBQcDAzB3BgNVHR8EcDBuMDWgM6Axhi9odHRwOi8vY3JsMy5kaWdpY2Vy
# dC5jb20vc2hhMi1hc3N1cmVkLWNzLWcxLmNybDA1oDOgMYYvaHR0cDovL2NybDQu
# ZGlnaWNlcnQuY29tL3NoYTItYXNzdXJlZC1jcy1nMS5jcmwwTAYDVR0gBEUwQzA3
# BglghkgBhv1sAwEwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQu
# Y29tL0NQUzAIBgZngQwBBAEwgYQGCCsGAQUFBwEBBHgwdjAkBggrBgEFBQcwAYYY
# aHR0cDovL29jc3AuZGlnaWNlcnQuY29tME4GCCsGAQUFBzAChkJodHRwOi8vY2Fj
# ZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRTSEEyQXNzdXJlZElEQ29kZVNpZ25p
# bmdDQS5jcnQwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAdHHzVcLG
# dSA7XSBpDwHelcVX/UxMufr1KZ7QIRAANGJNm78wxr/qiaOTTMu0Yb4eumOIdcwn
# K3L3kxlebUPh4vTiYcdaO5GbuGESS18xZ6qn0qFOCG25Grm2IJKU+cc2bl31XWdp
# nCaDtCKa5XkRxFlk2VXuA52cdqmGK+Gc6H+J/1EBlNhBbdguvcZJ/U1+JBTeuCgM
# MXbk5bRUEUrXjXwOt+XUXiqP2ENUAlv/4/uATxxE5VJAVeHulXtr7UsUcINIBD9w
# z8BpzvLbBVNNCn7/WGvcvtif7ShIYQgZ28dvaMto3kNNhPvT9aMDkGowTdzjl5xn
# ddzZhcJ0RxRr7jCCBmowggVSoAMCAQICEAMBmgI6/1ixa9bV6uYX8GYwDQYJKoZI
# hvcNAQEFBQAwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZ
# MBcGA1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNz
# dXJlZCBJRCBDQS0xMB4XDTE0MTAyMjAwMDAwMFoXDTI0MTAyMjAwMDAwMFowRzEL
# MAkGA1UEBhMCVVMxETAPBgNVBAoTCERpZ2lDZXJ0MSUwIwYDVQQDExxEaWdpQ2Vy
# dCBUaW1lc3RhbXAgUmVzcG9uZGVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
# CgKCAQEAo2Rd/Hyz4II14OD2xirmSXU7zG7gU6mfH2RZ5nxrf2uMnVX4kuOe1Vpj
# WwJJUNmDzm9m7t3LhelfpfnUh3SIRDsZyeX1kZ/GFDmsJOqoSyyRicxeKPRktlC3
# 9RKzc5YKZ6O+YZ+u8/0SeHUOplsU/UUjjoZEVX0YhgWMVYd5SEb3yg6Np95OX+Ko
# ti1ZAmGIYXIYaLm4fO7m5zQvMXeBMB+7NgGN7yfj95rwTDFkjePr+hmHqH7P7IwM
# Nlt6wXq4eMfJBi5GEMiN6ARg27xzdPpO2P6qQPGyznBGg+naQKFZOtkVCVeZVjCT
# 88lhzNAIzGvsYkKRrALA76TwiRGPdwIDAQABo4IDNTCCAzEwDgYDVR0PAQH/BAQD
# AgeAMAwGA1UdEwEB/wQCMAAwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwgwggG/BgNV
# HSAEggG2MIIBsjCCAaEGCWCGSAGG/WwHATCCAZIwKAYIKwYBBQUHAgEWHGh0dHBz
# Oi8vd3d3LmRpZ2ljZXJ0LmNvbS9DUFMwggFkBggrBgEFBQcCAjCCAVYeggFSAEEA
# bgB5ACAAdQBzAGUAIABvAGYAIAB0AGgAaQBzACAAQwBlAHIAdABpAGYAaQBjAGEA
# dABlACAAYwBvAG4AcwB0AGkAdAB1AHQAZQBzACAAYQBjAGMAZQBwAHQAYQBuAGMA
# ZQAgAG8AZgAgAHQAaABlACAARABpAGcAaQBDAGUAcgB0ACAAQwBQAC8AQwBQAFMA
# IABhAG4AZAAgAHQAaABlACAAUgBlAGwAeQBpAG4AZwAgAFAAYQByAHQAeQAgAEEA
# ZwByAGUAZQBtAGUAbgB0ACAAdwBoAGkAYwBoACAAbABpAG0AaQB0ACAAbABpAGEA
# YgBpAGwAaQB0AHkAIABhAG4AZAAgAGEAcgBlACAAaQBuAGMAbwByAHAAbwByAGEA
# dABlAGQAIABoAGUAcgBlAGkAbgAgAGIAeQAgAHIAZQBmAGUAcgBlAG4AYwBlAC4w
# CwYJYIZIAYb9bAMVMB8GA1UdIwQYMBaAFBUAEisTmLKZB+0e36K+Vw0rZwLNMB0G
# A1UdDgQWBBRhWk0ktkkynUoqeRqDS/QeicHKfTB9BgNVHR8EdjB0MDigNqA0hjJo
# dHRwOi8vY3JsMy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURDQS0xLmNy
# bDA4oDagNIYyaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJl
# ZElEQ0EtMS5jcmwwdwYIKwYBBQUHAQEEazBpMCQGCCsGAQUFBzABhhhodHRwOi8v
# b2NzcC5kaWdpY2VydC5jb20wQQYIKwYBBQUHMAKGNWh0dHA6Ly9jYWNlcnRzLmRp
# Z2ljZXJ0LmNvbS9EaWdpQ2VydEFzc3VyZWRJRENBLTEuY3J0MA0GCSqGSIb3DQEB
# BQUAA4IBAQCdJX4bM02yJoFcm4bOIyAPgIfliP//sdRqLDHtOhcZcRfNqRu8WhY5
# AJ3jbITkWkD73gYBjDf6m7GdJH7+IKRXrVu3mrBgJuppVyFdNC8fcbCDlBkFazWQ
# EKB7l8f2P+fiEUGmvWLZ8Cc9OB0obzpSCfDscGLTYkuw4HOmksDTjjHYL+NtFxMG
# 7uQDthSr849Dp3GdId0UyhVdkkHa+Q+B0Zl0DSbEDn8btfWg8cZ3BigV6diT5VUW
# 8LsKqxzbXEgnZsijiwoc5ZXarsQuWaBh3drzbaJh6YoLbewSGL33VVRAA5Ira8JR
# wgpIr7DUbuD0FAo6G+OPPcqvao173NhEMIIGzTCCBbWgAwIBAgIQBv35A5YDreoA
# Cus/J7u6GzANBgkqhkiG9w0BAQUFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMM
# RGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQD
# ExtEaWdpQ2VydCBBc3N1cmVkIElEIFJvb3QgQ0EwHhcNMDYxMTEwMDAwMDAwWhcN
# MjExMTEwMDAwMDAwWjBiMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQg
# SW5jMRkwFwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2Vy
# dCBBc3N1cmVkIElEIENBLTEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQDogi2Z+crCQpWlgHNAcNKeVlRcqcTSQQaPyTP8TUWRXIGf7Syc+BZZ3561JBXC
# mLm0d0ncicQK2q/LXmvtrbBxMevPOkAMRk2T7It6NggDqww0/hhJgv7HxzFIgHwe
# og+SDlDJxofrNj/YMMP/pvf7os1vcyP+rFYFkPAyIRaJxnCI+QWXfaPHQ90C6Ds9
# 7bFBo+0/vtuVSMTuHrPyvAwrmdDGXRJCgeGDboJzPyZLFJCuWWYKxI2+0s4Grq2E
# b0iEm09AufFM8q+Y+/bOQF1c9qjxL6/siSLyaxhlscFzrdfx2M8eCnRcQrhofrfV
# dwonVnwPYqQ/MhRglf0HBKIJAgMBAAGjggN6MIIDdjAOBgNVHQ8BAf8EBAMCAYYw
# OwYDVR0lBDQwMgYIKwYBBQUHAwEGCCsGAQUFBwMCBggrBgEFBQcDAwYIKwYBBQUH
# AwQGCCsGAQUFBwMIMIIB0gYDVR0gBIIByTCCAcUwggG0BgpghkgBhv1sAAEEMIIB
# pDA6BggrBgEFBQcCARYuaHR0cDovL3d3dy5kaWdpY2VydC5jb20vc3NsLWNwcy1y
# ZXBvc2l0b3J5Lmh0bTCCAWQGCCsGAQUFBwICMIIBVh6CAVIAQQBuAHkAIAB1AHMA
# ZQAgAG8AZgAgAHQAaABpAHMAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGUAIABjAG8A
# bgBzAHQAaQB0AHUAdABlAHMAIABhAGMAYwBlAHAAdABhAG4AYwBlACAAbwBmACAA
# dABoAGUAIABEAGkAZwBpAEMAZQByAHQAIABDAFAALwBDAFAAUwAgAGEAbgBkACAA
# dABoAGUAIABSAGUAbAB5AGkAbgBnACAAUABhAHIAdAB5ACAAQQBnAHIAZQBlAG0A
# ZQBuAHQAIAB3AGgAaQBjAGgAIABsAGkAbQBpAHQAIABsAGkAYQBiAGkAbABpAHQA
# eQAgAGEAbgBkACAAYQByAGUAIABpAG4AYwBvAHIAcABvAHIAYQB0AGUAZAAgAGgA
# ZQByAGUAaQBuACAAYgB5ACAAcgBlAGYAZQByAGUAbgBjAGUALjALBglghkgBhv1s
# AxUwEgYDVR0TAQH/BAgwBgEB/wIBADB5BggrBgEFBQcBAQRtMGswJAYIKwYBBQUH
# MAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBDBggrBgEFBQcwAoY3aHR0cDov
# L2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNy
# dDCBgQYDVR0fBHoweDA6oDigNoY0aHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0Rp
# Z2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDA6oDigNoY0aHR0cDovL2NybDQuZGln
# aWNlcnQuY29tL0RpZ2lDZXJ0QXNzdXJlZElEUm9vdENBLmNybDAdBgNVHQ4EFgQU
# FQASKxOYspkH7R7for5XDStnAs0wHwYDVR0jBBgwFoAUReuir/SSy4IxLVGLp6ch
# nfNtyA8wDQYJKoZIhvcNAQEFBQADggEBAEZQPsm3KCSnOB22WymvUs9S6TFHq1Zc
# e9UNC0Gz7+x1H3Q48rJcYaKclcNQ5IK5I9G6OoZyrTh4rHVdFxc0ckeFlFbR67s2
# hHfMJKXzBBlVqefj56tizfuLLZDCwNK1lL1eT7EF0g49GqkUW6aGMWKoqDPkmzmn
# xPXOHXh2lCVz5Cqrz5x2S+1fwksW5EtwTACJHvzFebxMElf+X+EevAJdqP77BzhP
# DcZdkbkPZ0XN1oPt55INjbFpjE/7WeAjD9KqrgB87pxCDs+R1ye3Fu4Pw718CqDu
# LAhVhSK46xgaTfwqIa1JMYNHlXdx3LEbS0scEJx3FMGdTy9alQgpECYxggQ7MIIE
# NwIBATCBhjByMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkw
# FwYDVQQLExB3d3cuZGlnaWNlcnQuY29tMTEwLwYDVQQDEyhEaWdpQ2VydCBTSEEy
# IEFzc3VyZWQgSUQgQ29kZSBTaWduaW5nIENBAhABqswZbX9JOj3ejVMRYZ4OMAkG
# BSsOAwIaBQCgeDAYBgorBgEEAYI3AgEMMQowCKACgAChAoAAMBkGCSqGSIb3DQEJ
# AzEMBgorBgEEAYI3AgEEMBwGCisGAQQBgjcCAQsxDjAMBgorBgEEAYI3AgEVMCMG
# CSqGSIb3DQEJBDEWBBRE2xWBbV6I0N5LOSBGIHphA8Qk2DANBgkqhkiG9w0BAQEF
# AASCAQBx0NZepXFfXRZ5A2nf4rFBHDKPgK1obc0ZWZmxwquTCVMDcSyoFf0K5W9e
# 7oEGmvtqSAWIUa1bSfAMvWOInSqVZbU6Vxg0Ks72kC9HrwuaD2AFWbmDSb4076NB
# xuFG2JhCjzLli2CbN5k5Ac52rE2y4zoULqY2Llbzla2PXftd/d0LymUErcRYFwXU
# AEoJIwizFj2esWoMYUU2yqRiLfrKtyiEEhKAqVwOL9FZio7vqcLm6ChMiR20xPvk
# UUngKK5q0AFq9zpoDZSpQmmA8zUw7BdmZ8xx+S2Jrh1LiTO7sjH8klXyq1KjswQ6
# HeHt4QiJ7vILNzce+/Z8uCKhBBGSoYICDzCCAgsGCSqGSIb3DQEJBjGCAfwwggH4
# AgEBMHYwYjELMAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcG
# A1UECxMQd3d3LmRpZ2ljZXJ0LmNvbTEhMB8GA1UEAxMYRGlnaUNlcnQgQXNzdXJl
# ZCBJRCBDQS0xAhADAZoCOv9YsWvW1ermF/BmMAkGBSsOAwIaBQCgXTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0xNzA5MjIyMjQzNDRa
# MCMGCSqGSIb3DQEJBDEWBBTb3xeC3ZURhL6gg8EPIiQa72+yATANBgkqhkiG9w0B
# AQEFAASCAQAbbHn3aJUt029rf16/hkcnU0Up6tFKNMN4CiwJnNLQ3CT8ZQo5LeRw
# Q7f8nq4FXPTjjFBsEVmeBt88WCfaUQGkSksgpInr2wp8K1EYZZHde3TK2pZMOULv
# EqU8ns/wgy9FUJOKyiwngo03L/Ne8gvYvjRkTxBAHRhprCbN5/1pZ3/pIZtbH9xK
# 8AQcATnVwJ2c0V19IyZVyiINMeS0sxeBRA60fk/6zOtH9VSXv60Rslcf8q6VheE1
# aTzpfiZl7i73CtPlDOLPvTtESNP1PVAEKsT2OOP66YEOl2s1VWKUD2pxYrUem6R1
# qnauaTUnptzRyZbryRipWPN3iLzNUcXL
# SIG # End signature block
