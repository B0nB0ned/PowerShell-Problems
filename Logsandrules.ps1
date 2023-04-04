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
