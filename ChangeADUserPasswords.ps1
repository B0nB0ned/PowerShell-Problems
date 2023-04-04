function Set-ADUserPassword {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$UserNames,
        
        [Parameter(Mandatory = $true)]
        [string]$NewPassword
    )
    
    # Prompt for the administrator credentials
    $Credential = Get-Credential -Message "Enter the administrator credentials for the domain"

    # Loop through each user and set the new password
    foreach ($UserName in $UserNames) {
        try {
            # Get the user object from Active Directory
            $User = Get-ADUser -Identity $UserName -Credential $Credential -ErrorAction Stop
            
            # Set the new password for the user
            $User | Set-ADAccountPassword -NewPassword (ConvertTo-SecureString -String $NewPassword -AsPlainText -Force) -Credential $Credential -Reset -ErrorAction Stop
            
            Write-Host "Password changed for user $UserName"
        }
        catch {
            Write-Host "Error changing password for user $UserName: $_" -ForegroundColor Red
        }
    }
}
#Set-ADUserPassword -UserNames "User1", "User2", "User3" -NewPassword "NewPassword123"

function Get-ADUserNames {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainController
    )

    # Get all user objects from Active Directory
    $Users = Get-ADUser -Filter * -Server $DomainController

    # Extract the usernames from the user objects
    $UserNames = $Users | Select-Object -ExpandProperty SamAccountName

    # Output the usernames as an array
    return $UserNames
}
#Get-ADUserNames -DomainController "dc1.example.com"

function Get-DomainControllerName {
    [CmdletBinding()]
    param()

    # Get the domain controller name for the current computer
    $DomainControllerName = (Get-WmiObject -Class Win32_ComputerSystem -Property DomainControllerName).DomainControllerName

    # Output the domain controller name
    return $DomainControllerName
}
#Get-DomainControllerName



#-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
#Get-DomainControllerName = $DCname | Get-ADUserNames -DomainController $DCname = $UserArray | Set-ADUserPassword -UserNames $UserArray -NewPassword “DeFaUlT_Ad_PaSsWoRd_2_HaRd”