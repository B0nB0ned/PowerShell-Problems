function Get-WifiPasswords {
    $profiles = (netsh wlan show profiles) | Select-String "\:(.+)$" | ForEach-Object {
        $name = $_.Matches.Groups[1].Value.Trim()
        $_
    }
    $passwords = $profiles | ForEach-Object {
        (netsh wlan show profile name="$name" key=clear) | Select-String "Key Content\W+\:(.+)$" | ForEach-Object {
            $pass = $_.Matches.Groups[1].Value.Trim()
            [PSCustomObject]@{ PROFILE_NAME=$name;PASSWORD=$pass }
        }
    }
    $passwords | Format-Table -AutoSize
}
Function Get-WinlogonDefault {
    gp 'HKLM:\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon' | select "Default*"
}
function Set-MAC {
	Set-NetAdapter -Name "Ethernet0" -MacAddress "00-01-18-57-1B-0D"
}
function Enable-RDP {
    # Allow RDP connections
    (Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices).SetAllowTsConnections(1)

    # Disable NLA
    (Get-WmiObject -class "Win32_TSGeneralSetting" -Namespace root\cimv2\terminalservices -Filter "TerminalName='RDP-tcp'").SetUserAuthenticationRequired(0)

    # Allow RDP on the firewall
    Get-NetFirewallRule -DisplayGroup "Remote Desktop" | Set-NetFirewallRule -Enabled True
}
function Get-IpHostname {
    param(
        [string]$net
    )

    $output = 0..255 | foreach {
        $ip = "$net$_"
        $result = (Resolve-DNSname -ErrorAction SilentlyContinue $ip | ft NameHost -HideTableHeaders | Out-String).trim().replace("\s+","").replace("`r","").replace("`n"," ")
        Write-Output "$ip $result"
        $result
    }
    $output | tee ip_hostname.txt
}
Function Test-OpenPorts {
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$True, Position=0)]
        [string]$IP,

        [Parameter(Mandatory=$True, Position=1)]
        [string]$Ports
    )
    $Ports.Split(" ") | ForEach-Object {
        if ((new-object Net.Sockets.TcpClient).Connect($IP, $_)) {
            Write-Output "Port $_ is open on $IP"
        }
        else {
            Write-Output "Port $_ is closed on $IP"
        }
    }
}
function Invoke-Url {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true, Position=0)]
        [string]$Url
    )

    $response = Invoke-WebRequest -Uri $Url
    $result = Invoke-Expression -Command $response.Content

    return $result
}
function Install-Git {
    [CmdletBinding()]
    param()

    # Check if Git is already installed
    if (Get-Command "git" -ErrorAction SilentlyContinue) {
        Write-Host "Git is already installed."
        return
    }

    # Download the Git installer
    $url = "https://github.com/git-for-windows/git/releases/download/v2.33.1.windows.1/Git-2.33.1-64-bit.exe"
    $outputFile = "$($env:TEMP)\GitInstaller.exe"
    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($url, $outputFile)

    # Install Git silently
    $arguments = "/VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS /COMPONENTS='icons,ext\reg\shellhere,assoc,assoc_sh'"
    Start-Process -FilePath $outputFile -ArgumentList $arguments -Wait

    # Verify that Git is installed
    if (Get-Command "git" -ErrorAction SilentlyContinue) {
        Write-Host "Git installed successfully."
    }
    else {
        Write-Error "Failed to install Git."
    }

    # Remove the installer
    Remove-Item $outputFile
}
function Uninstall-Git {
    [CmdletBinding()]
    param()

    # Check if Git is installed
    if (!(Get-Command "git" -ErrorAction SilentlyContinue)) {
        Write-Host "Git is not installed."
        return
    }

    # Uninstall Git silently
    $uninstallKey = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Git_is1"
    $uninstallString = (Get-ItemProperty -Path $uninstallKey -Name UninstallString).UninstallString
    $arguments = "/VERYSILENT /NORESTART /NOCANCEL /SP- /CLOSEAPPLICATIONS /RESTARTAPPLICATIONS"
    Start-Process -FilePath $uninstallString -ArgumentList $arguments -Wait

    # Verify that Git is uninstalled
    if (!(Get-Command "git" -ErrorAction SilentlyContinue)) {
        Write-Host "Git uninstalled successfully."
    }
    else {
        Write-Error "Failed to uninstall Git."
    }
}
function Enable-FirewallLogs {
    # Enable Windows Firewall logs
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
}
#Enable-FirewallLogs
function Restore-FirewallRules {
    # Disable the Windows Firewall service temporarily
    Set-Service -Name MpsSvc -StartupType Disabled

    # Restore the default Windows Firewall settings
    netsh advfirewall reset

    # Re-enable the Windows Firewall service
    Set-Service -Name MpsSvc -StartupType Automatic
    Start-Service -Name MpsSvc
}
#Restore-DefaultFirewall
function Import-FirewallRules {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
        [string]$Path
    )
    try {
        # Import the WFAS policy file
        Import-NetFirewallRule -PolicyStore $Path -ErrorAction Stop

        # Activate the imported firewall rules
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True -ErrorAction Stop

        Write-Host "Firewall rules imported and activated successfully."
    } catch {
        Write-Error "Failed to import and activate firewall rules: $_"
    }
}
#Import-FirewallRules -Path "C:\temp\myfirewallrules.wfw"
function Set-Syslog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ServerAddress,
        
        [Parameter(Mandatory = $true)]
        [int]$Port,
        
        [Parameter(Mandatory = $true)]
        [string]$Protocol
    )

    # Set the registry keys to enable syslog forwarding
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "AutoBackupLogFiles" -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security" -Name "MaxSize" -Value 0x800000
    
    # Install the syslog agent
    Install-Package -Name SyslogAgent -ProviderName 'NuGet' -Force

    # Set the syslog configuration
    $Config = @{
        ServerAddress = $ServerAddress
        Port = $Port
        Protocol = $Protocol
    }
    Set-SyslogAgentConfig @Config

    # Start the syslog service
    Start-Service -Name syslogagent
}
#Set-Syslog -ServerAddress "syslog.example.com" -Port 514 -Protocol UDP
function Enable-DNSLogging {
    [CmdletBinding()]
    param()

    # Enable DNS debug logging
    $DnsServer = Get-WmiObject -Namespace "root\MicrosoftDNS" -Class "MicrosoftDNS_Server"
    $DnsServer.DebugLogging = $true
    $DnsServer.DebugFile = "C:\Windows\System32\dns\dns.log"
    $DnsServer.DebugLevel = 0
    $DnsServer.Put()

    # Enable DNS query logging
    $RegistryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters"
    $Values = @{
        "LogFilePath" = "C:\Windows\System32\dns\dnsquery.log"
        "EnableLogging" = 1
        "LogIncomingRequests" = 1
        "LogOutgoingResponses" = 1
        "LogLevel" = 2
    }
    $Values.GetEnumerator() | ForEach-Object {
        Set-ItemProperty -Path $RegistryPath -Name $_.Key -Value $_.Value -Force
    }

    # Restart the DNS service
    Restart-Service -Name DNS -Force
}
#Enable-DNSLogging
function Enable-ADEnhancedLogging {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DomainController
    )

    # Enable directory service access auditing
    $AuditPolicy = Get-AuditPolicy
    $AuditPolicy.DirectoryServiceAccess = "Success,Failure"
    Set-AuditPolicy -AuditPolicy $AuditPolicy

    # Enable directory service changes auditing
    $NTDSObject = Get-ADObject "CN=NTDS Settings,CN=$DomainController,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=example,DC=com" -Properties "options"
    $Options = $NTDSObject.options
    $Options[5] = $Options[5] -bor 0x20
    Set-ADObject -Instance $NTDSObject

    # Enable detailed tracking of security events
    $GPO = Get-GPO -Name "Default Domain Controllers Policy" -Server $DomainController
    $SecuritySettings = $GPO.ExtensionData.Extension.SecuritySettings
    $AuditPolicy = $SecuritySettings.AuditPolicy
    $AuditPolicy.AuditDetailedTracking = "Enabled"
    $SecuritySettings.AuditPolicy = $AuditPolicy
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -ValueName "ProcessCreationIncludeCmdLine_Enabled" -Type DWORD -Value 1

    # Refresh the group policy on the domain controller
    Invoke-GPUpdate -Computer $DomainController -Target "Computer"

    # Restart the domain controller to apply the changes
    Restart-Computer -ComputerName $DomainController -Force
}
#Enable-ADEnhancedLogging -DomainController "dc1.example.com"
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
function Import-FirewallRules {
    param(
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

    # Import the firewall rules from the WFW file
    Import-NetFirewallRule -Path $FilePath

    # Enable the newly imported firewall rules
    Get-NetFirewallRule | Where-Object {$_.Enabled -eq $false} | Enable-NetFirewallRule
}
function Restore-DefaultFirewall {
    # Disable the Windows Firewall service temporarily
    Set-Service -Name MpsSvc -StartupType Disabled

    # Restore the default Windows Firewall settings
    netsh advfirewall reset

    # Re-enable the Windows Firewall service
    Set-Service -Name MpsSvc -StartupType Automatic
    Start-Service -Name MpsSvc
}
function Enable-FirewallLogs {
    # Enable Windows Firewall logs
    Set-NetFirewallProfile -Profile Domain,Public,Private -LogAllowed True
}
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