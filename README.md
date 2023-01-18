# DCOMPermissions
This module is used to modify Launch and Activation Permissions and/or Access Permissions on DCOM objects.

**Note:**  Some objects such as {9CA88EE3-ACB7-47C8-AFC4-AB702511C276} (RuntimeBroker) do not grant Administrators configuration permission to change the DCOM permissions.  These objects are usually owned by TrustedInstaller or SYSTEM.  The cmdlets in this module will work around this problem when the -Override switch has been specified.

Original source: https://web.archive.org/web/20200317010413/https://gallery.technet.microsoft.com/Grant-Revoke-Get-DCOM-22da5b96
