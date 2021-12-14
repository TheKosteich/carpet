<#
SCRIPTNAME: Check-AD.ps1
AUTHOR: Konstantin Tornovskii

Last Updated: 07/12/2021
Version 0.0.1

This script is designed for capturing data from Active Directory. Script running
result is common AD infrastracture weakness.

This script requires the following:
 * PowerShell 5.0
 * Active Directory PowerShell Module
 * Group Policy PowerShell Module
#>

# Load required modules
Import-Module ActiveDirectory
Import-Module GroupPolicy

## Set constants
Param
 (
    $DomainName = (Get-ADDomain).DNSRoot,
    $ReportsDirectory = 'c:\tmp\CheckAD-Reports',

    [int]$UserLogonAge = '180',
    [int]$UserPasswordAge = '180'

 )

$DateTime = get-date -uformat "%Y-%m-%d-%H-%M"

## Custom functions
# Source https://blog.wobl.it/2016/04/active-directory-guid-to-friendly-name-using-just-powershell/
function Get-NameForGUID{
	[CmdletBinding()]
	Param(
		[guid]$guid
	)
	Begin{
		$DomainDC = ([ADSI]"").distinguishedName
		$ExtendedRightGUIDs = "LDAP://cn=Extended-Rights,cn=configuration,$DomainDC"
		$PropertyGUIDs = "LDAP://cn=schema,cn=configuration,$DomainDC"
	}
	Process{
		If($guid -eq "00000000-0000-0000-0000-000000000000"){
			Return "All"
		}Else{
			$rightsGuid = $guid
			$property = "cn"
			$SearchAdsi = ([ADSISEARCHER]"(rightsGuid=$rightsGuid)")
			$SearchAdsi.SearchRoot = $ExtendedRightGUIDs
			$SearchAdsi.SearchScope = "OneLevel"
			$SearchAdsiRes = $SearchAdsi.FindOne()
			If($SearchAdsiRes){
				Return $SearchAdsiRes.Properties[$property]
			}Else{
				$SchemaGuid = $guid
				$SchemaByteString = "\" + ((([guid]$SchemaGuid).ToByteArray() | %{$_.ToString("x2")}) -Join "\")
				$property = "ldapDisplayName"
				$SearchAdsi = ([ADSISEARCHER]"(schemaIDGUID=$SchemaByteString)")
				$SearchAdsi.SearchRoot = $PropertyGUIDs
				$SearchAdsi.SearchScope = "OneLevel"
				$SearchAdsiRes = $SearchAdsi.FindOne()
				If($SearchAdsiRes){
					Return $SearchAdsiRes.Properties[$property]
				}Else{
					Write-Host -f Yellow $guid
					Return $guid.ToString()
				}
			}
		}
	}
}


function Get-RightsInAD{
	[CmdletBinding()]
	Param(
		[string]$UserName,
		[string]$DomainDC = ([ADSI]"").distinguishedName,
		[string]$UserPath = "OU=Users,OU=Accounts,$DomainDC"
	)

	#Set Verbose and Debug params
	if (-not $PSBoundParameters.ContainsKey('Verbose'))
	{
		$VerbosePreference = $PSCmdlet.GetVariableValue('VerbosePreference')
	}else{
		$VerbosePreference = [System.Management.Automation.ActionPreference]::Continue
	}
	if (-not $PSBoundParameters.ContainsKey('Debug'))
	{
		$DebugPreference = $PSCmdlet.GetVariableValue('DebugPreference')
	}else{
		$DebugPreference = [System.Management.Automation.ActionPreference]::Continue
	}


	If( ![System.String]::IsNullOrEmpty($UserName) ){
		$iBackSlash = $UserName.IndexOf("\")
		if(($iBackSlash -ne "-1"))
		{
			$UserName = ($UserName.Split('\'))[1]
		}
		$AccountEntry = ([ADSISEARCHER]"samaccountname=$UserName").Findone()
		If($AccountEntry.Path){
			$DistinguishedNamePath = $AccountEntry.Properties["distinguishedName"]
		}Else{
			Throw "FAILED TO RETRIEVE USER FROM AD BY SAM ACCOUNTNAME $UserName"
		}
		$Groups = @(Get-UserGroupsInAD $DistinguishedNamePath)
		$Groups += $UserName
	}

	$UserAccountsPath = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$UserPath")
	if(!$UserAccountsPath.Path){
		Throw "FAILED TO RETRIEVE USER ACCOUNT OU FROM AD BY PATH $UserPath"
	}
	$AccessRuleCollection = $Entry.PSBase.ObjectSecurity.Access | ?{$_.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow} | ?{$_.IdentityReference -is [System.Security.Principal.NTAccount]}

	If( ![System.String]::IsNullOrEmpty($UserName) ){
		$AccessRuleCollection = $AccessRuleCollection | ?{$Groups -Contains $_.IdentityReference.ToString().Split("\")[-1]}
	}
	$AccessRights = @()
	$AccessRuleCollection | %{
		If($_.ActiveDirectoryRights -eq "GenericAll"){
			$AccessPermissions = "All"
		}ElseIf($_.ActiveDirectoryRights -eq "ExtendedRight" -or $_.ActiveDirectoryRights -Match "ExtendedRight"){
			$AccessPermissions = "Special"
		}Else{
			$AccessPermissions = $_.ActiveDirectoryRights.ToString()
		}
		$AccessProperties = Get-NameForGUID $_.ObjectType
		$AccessObject = Get-NameForGUID $_.InheritedObjectType

		$AccessRights += @{
			Permissions = $AccessPermissions;
			Properties = $AccessProperties;
			Object = $AccessObject;
			ActiveDirectoryRights = $_.ActiveDirectoryRights;
			IdentityReference = $_.IdentityReference
		}
	}
	Return $AccessRights
}

Write-Host "Initializing..." -Fore Blue

# Create reports directory if not
IF (!(Test-Path $ReportsDirectory)) {
    new-item -type Directory -path $ReportsDirectory
	Write-Host "Created reports directory - $ReportsDirectory" -Fore Green
}

# Write all output in to file
$Report = $ReportsDirectory + "\CheckAD-Report-$DateTime.txt"
Start-Transcript $Report
Write-Host "Started logging to file - $Report" -Fore Green

# Get Domain info
$DomainInfo = Get-ADDomain $DomainName
$DomainPDC = $DomainInfo.PDCEmulator
$DomainNetBIOSName = $DomainInfo.NetBIOSName
$DomainDN = $DomainInfo.DistinguishedName

# Get Forest info
$ForestDNSName = (Get-ADForest).Name

Write-Host "Starting checks for $DomainName..." -Fore Blue

Write-Host ""

# Get Forest Functional Level
$ForestFunctionalLevel = (Get-ADForest).ForestMode
$DomainFunctionalLevel = (Get-ADDomain $DomainName).DomainMode
Write-Host "Forest Functional Level: $ForestFunctionalLevel `n" -Fore Blue
Write-Host "Domain Functional Level: $DomainFunctionalLevel `n" -Fore Blue

Write-Host ""

# Get Domain Controllers
$DomainControllers = Get-ADDomainController -filter *
Write-Host "$DomainName Domain Controllers and OS:  `n" -Fore Blue
$DomainControllers | Select HostName,OperatingSystem | Format-Table -AutoSize

Write-Host ""

# Get Domain Users
$RequredProperties = @("Name","Enabled","SAMAccountname","DisplayName","Enabled",
"LastLogonDate", "PasswordLastSet", "PasswordNeverExpires","PasswordNotRequired",
"PasswordExpired", "SmartcardLogonRequired", "AccountExpirationDate","AdminCount",
"Created","Modified", "LastBadPasswordAttempt", "badpwdcount","mail", "CanonicalName",
"DistinguishedName", "ServicePrincipalName","SIDHistory","PrimaryGroupID","UserAccountControl")

$DomainUsers = get-aduser -filter * -Property $RequredProperties
Write-Host "Total domain users count: $($DomainUsers.count)" -Fore Blue

$EnabledUsers = $DomainUsers | Where {$_.Enabled -eq $True }
Write-Host "Enabled domain users count: $($EnabledUsers.count)" -Fore Blue

$LastLogonDate = $(Get-Date) - $(New-TimeSpan -days $UserLogonAge)
$LastPasswordChangeDate = $(Get-Date) - $(New-TimeSpan -days $UserPasswordAge)

$InactiveEnabledUsers = $EnabledUsers | Where { ($_.LastLogonDate -le $LastLogonDate) -AND `
		($_.PasswordLastSet -le $LastPasswordChangeDate) }
Write-Host "Inactive enabled users count: $($InactiveEnabledUsers.count)" -Fore Blue

$PasswordNeverExpireUsers = $DomainUsers | Where {$_.PasswordNeverExpires -eq $True}
Write-Host "Users count with  password never expired: $($PasswordNeverExpireUsers.count)" -Fore Blue

$PasswordNotRequiredUsers = $DomainUsers | Where {$_.PasswordNotRequired -eq $True}
Write-Host "Users count with password not required: $($PasswordNotRequiredUsers.count)" -Fore Blue

$ReversibleEncryptionPasswordUsers = $DomainUsers | Where { $_.UserAccountControl -band 0x0080 }
Write-Host "Users count with reversible encrypted password: $($ReversibleEncryptionPasswordUsers.count)" -Fore Blue

$SIDHistoryUsers = $DomainUsers | Where {$_.SIDHistory -like "*"}
Write-Host "Users count with SID history: $($SIDHistoryUsers.count)" -Fore Blue

$KerberosDESUsers = $DomainUsers | Where { $_.UserAccountControl -band 0x200000 }
Write-Host "Users count with Kerberos DES setted: $($KerberosDESUsers.count)" -Fore Blue

$NotRequirePreAuthUsers = $DomainUsers | Where {$_.DoesNotRequirePreAuth -eq $True}
Write-Host "User count with not required Kerberos Pre-authentication: $($NotRequirePreAuthUsers.count)" -Fore Blue

Write-Host ""

# Get domain password policy
Write-Host "$DomainName Password Policy" -Fore Blue
$PasswordPolicy = Get-ADDefaultDomainPasswordPolicy
Write-Output $PasswordPolicy

# Get domain admins
$DomainAdminsSID = "$($DomainInfo.DomainSID)-500"
$DefaultDomainAdmin = Get-ADUser $DomainAdminsSID -Properties Name,Enabled,Created,PasswordLastSet,LastLogonDate,ServicePrincipalName,SID
Write-Host "Default Domain Admin username: $($DefaultDomainAdmin.name)" -Fore Blue
$DefaultDomainAdmin | Select Enabled,Created,PasswordLastSet,LastLogonDate | Format-Table -AutoSize

Write-Host "Trying to find other Domain Admins..." -Fore Yellow
$DomainAdmins = ""

try
	{
		$DomainAdmins = Get-ADGroupMember Administrators -Recursive
	}
catch
	{
		Write-Host 'Domain group "Administrators" not found!!!' -Fore Red
		Write-Host 'Trying to find in group "администраторы"...' -Fore Yellow
	}

try
	{
		$DomainAdmins = Get-ADGroupMember "администраторы" -Recursive
	}
catch
	{
		Write-Host 'Domain group "администраторы" not found!!!' -Fore Red
		Write-Host 'Try to find other Domain Admins manually.' -Fore Red
	}

if ($DomainAdmins)
	{
		$DomainAdminsArray = @()
		foreach($DomainAdmin in $DomainAdmins)
			{
				Switch ($DomainAdmin.objectClass)
					{
						'User' { [array]$DomainAdminsArray += Get-ADUser $DomainAdmin -Properties LastLogonDate,PasswordLastSet,ServicePrincipalName }
					}
			}
		Write-Host " "
		Write-Host "Other Domain Admins: " -Fore Blue
		$DomainAdminsArray | sort PasswordLastSet | select name,DistinguishedName,PasswordLastSet,LastLogonDate | Format-Table -AutoSize
	}
else
	{
		Write-Host 'No other Domain Admins found!' -Fore Red
		Write-Host 'Try to find other Domain Admins manually.' -Fore Red
	}
