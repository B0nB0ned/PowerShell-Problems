# Create the Get-NetFirewall folder
New-Item -ItemType Directory -Path ".\Get-NetFirewall" -Force | Out-Null

# Export the output of each cmdlet to its own file in the Get-NetFirewall folder
Get-NetFirewallAddressFilter | Export-Csv -Path ".\Get-NetFirewall\AddressFilter.csv" -NoTypeInformation
Get-NetFirewallApplicationFilter | Export-Csv -Path ".\Get-NetFirewall\ApplicationFilter.csv" -NoTypeInformation
Get-NetFirewallDynamicKeywordAddress | Export-Csv -Path ".\Get-NetFirewall\DynamicKeywordAddress.csv" -NoTypeInformation
Get-NetFirewallHyperVPort | Export-Csv -Path ".\Get-NetFirewall\HyperVPort.csv" -NoTypeInformation
Get-NetFirewallHyperVRule | Export-Csv -Path ".\Get-NetFirewall\HyperVRule.csv" -NoTypeInformation
Get-NetFirewallHyperVVMCreator | Export-Csv -Path ".\Get-NetFirewall\HyperVVMCreator.csv" -NoTypeInformation
Get-NetFirewallHyperVVMSetting | Export-Csv -Path ".\Get-NetFirewall\HyperVVMSetting.csv" -NoTypeInformation
Get-NetFirewallInterfaceFilter | Export-Csv -Path ".\Get-NetFirewall\InterfaceFilter.csv" -NoTypeInformation
Get-NetFirewallInterfaceTypeFilter | Export-Csv -Path ".\Get-NetFirewall\InterfaceTypeFilter.csv" -NoTypeInformation
Get-NetFirewallPortFilter | Export-Csv -Path ".\Get-NetFirewall\PortFilter.csv" -NoTypeInformation
Get-NetFirewallProfile | Export-Csv -Path ".\Get-NetFirewall\Profile.csv" -NoTypeInformation
Get-NetFirewallRule | Export-Csv -Path ".\Get-NetFirewall\Rule.csv" -NoTypeInformation
Get-NetFirewallSecurityFilter | Export-Csv -Path ".\Get-NetFirewall\SecurityFilter.csv" -NoTypeInformation
Get-NetFirewallServiceFilter | Export-Csv -Path ".\Get-NetFirewall\ServiceFilter.csv" -NoTypeInformation
