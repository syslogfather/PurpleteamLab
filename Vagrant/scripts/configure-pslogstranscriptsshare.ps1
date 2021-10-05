Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) Configuring the Powershell Transcripts Share"
If (-not (Test-Path c:\pslogs))
{
    md c:\pslogs
}


$acl = Get-Acl c:\pslogs
$acl.SetAccessRuleProtection($true, $false)


$administrators = [System.Security.Principal.NTAccount] "Administrators"
$permission = $administrators,"FullControl","ObjectInherit,ContainerInherit","None","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.AddAccessRule($accessRule)


$everyone = [System.Security.Principal.NTAccount] "Everyone"
$permission = $everyone,"Write,ReadAttributes","ObjectInherit,ContainerInherit","None","Allow"
$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
$acl.AddAccessRule($accessRule)


#$creatorOwner = [System.Security.Principal.NTAccount] "Creator Owner"
#$permission = $creatorOwner,"FullControl","ObjectInherit,ContainerInherit","InheritOnly","Deny"
#$accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
#$acl.AddAccessRule($accessRule)

$acl | Set-Acl c:\pslogs\

if ((Get-SmbShare -Name pslogs -ea silent) -eq $null)
{
    New-SmbShare -Name pslogs -Path c:\pslogs -ChangeAccess Everyone
}
