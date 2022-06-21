#Run this script in a powershell terminal with elevated privilages.
#
#This Script will:
###Create User Object in Active Directory
###Create User Mailbox within On-Premises Exchange
###Connect and Run AdSync on SERVERFQDN
#
#Onboarding V1 Script handles On-Premises Provisioning, V2 Script will include O365 migration.  
##PowerShelled by JB##

#Collect SamAccount info.
$SamAccount = Read-Host "What is the user's username?"

#Check if SamAccount exists and create account if it does not.
if (!(Get-ADUser -Server SERVERFQDN -Filter "sAMAccountName -eq '$($SamAccount)'"))
    {
        Write-Warning "User does not exist."
        $FirstName = Read-Host "What is the user's first name?" 
        $MiddleInitial = Read-Host "What is the user's middle initial?"
        $LastName = Read-Host "What is the user's LastName?" 
        $Office = Read-Host "What is office is the user in?"
        $Title = Read-Host "What is the user's Title?" 
        #$Role = Read-Host "What is the user's Role?" #Need to write the logic for this feature.
        $password = Read-Host "Enter Temp Password" -AsSecureString  #Create Mailbox 
        Write-Warning "Need your Admin Credentials in order to proceed!"
        $Credentials = Get-Credential 

        #Declared Variables
        Write-Warning "Getting fancy with the information you input!"
        $Upn = "$SamAccount@YOURDOMAIN.com"
        $Name = "$LastName, $FirstName"
        Write-Warning "Connecting to On-Prem Exchange Server!"
        $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri http://YOUREXCH/PowerShell/ -Authentication Kerberos -Credential $Credentials 

        #Create Mailbox
        Write-Warning "Creating On-Prem User Mailbox!"
        Import-PSSession $Session
        New-Mailbox -UserPrincipalName $Upn -Alias $SamAccount -Database "YOUREXCHDB" -Name $Name -OrganizationalUnit 'YOURDOMAIN/OU/OU' -Password $password -FirstName $FirstName -LastName $LastName -DisplayName $Name -ResetPasswordOnNextLogon $false
        Remove-PSSession $Session

        #Get & Set User Attributes
        Write-Warning "Setting AD User Object Attributes!"
        Get-ADUser $SamAccount -Server SERVERFQDN
        Set-ADUser $SamAccount -Server SERVERFQDN -Initials $MiddleInitial -Description $Title -Office $Office -Title $Title

        #Get Set Get Group Memberships
        Write-Warning "Assinging General Group Memberships to AD User Object!"
        Get-ADPrincipalGroupMembership $SamAccount -Server SERVERFQDN
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount
        Add-ADGroupMember -Identity GROUPNAME -Server SERVERFQDN -Members $SamAccount

        #AdSync
        Write-Warning "Running Delta ADSync so you don't have to!"
        $AdSyncSession = New-PSSession -ComputerName YOURADSYNCSERVER -Credential $Credentials
        $AdSyncSession
        Start-Sleep -Seconds 5
        Invoke-Command -Session $AdSyncSession -ScriptBlock {Import-Module adsync}
        Invoke-Command -Session $AdSyncSession -ScriptBlock {Start-adsyncsynccycle -policytype delta}
        Exit-PSSession
    }
    
else       
    { 
        Write-Warning "You're going to have a bad day, $SamAccount already exists in Active Directory! Try Again with a different username."  
    }

