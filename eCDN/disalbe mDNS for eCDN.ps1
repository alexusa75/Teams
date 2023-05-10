<#
.SYNOPSIS
This script configures a Windows computer for Microsoft eCDN.

.DESCRIPTION
This script adds registry keys to a Windows computer for disabling WebRTC's IP obfuscation behavior solely for the Microsoft eCDN domain on the following browsers:
    - Microsoft Edge
    - Google Chrome
    - Mozilla Firefox

Without these registry keys (or other applicable configuartions) the browsers will obfuscate the viewer's IP address which will ultimately prevent the eCDN client from connecting to peers.

.PARAMETER eCDN_domain
The eCDN domain to add to the registry keys. Default is *.ecdn.microsoft.com

.EXAMPLE
& '.\disalbe mDNS for eCDN.ps1'

.NOTES
As of June 1st 2023, the domain in this script should be updated to *.ecdn.teams.microsoft.com
By July 1st 2023, the domain migration should be complete and the old domain will be deprecated.

.OUTPUTS
None

.INPUTS
None

.LINK
See more regarding disabling mDNS for Microsoft eCDN here: https://learn.microsoft.com/ecdn/how-to/disable-mdns
This script is based on a version by Alexusa75 found here: https://github.com/alexusa75/Teams
#>
[cmdletbinding()] param(
    [Parameter(Mandatory=$false, HelpMessage="Specify the eCDN domain to add to the registry keys. Default is *.ecdn.microsoft.com")]
    [string]
    $eCDN_domain = "*.ecdn.microsoft.com"
)

$HKLM_SW_Policies_Path = "HKLM:\SOFTWARE\Policies"


$browser_list = @(
    @{
        name = "Microsoft Edge";
        executable = "msedge.exe"; 
        reg_path = "$HKLM_SW_Policies_Path\Microsoft\Edge"; # keeping here for reference
        webRTCkey = "WebRtcLocalIpsAllowedUrls"
    },
    @{
        name = "Google Chrome";
        executable = "chrome.exe"; 
        reg_path = "$HKLM_SW_Policies_Path\Google\Chrome";
        webRTCkey = "WebRtcLocalIpsAllowedUrls"
    },
    @{
        name = "Mozilla Firefox";
        executable = "firefox.exe"; 
        reg_path = "$HKLM_SW_Policies_Path\Mozilla\Firefox";
        webRTCkey = "Preferences"
    }
)

if (-not [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")) {
    Write-Host "This script must be run as an Administrator" -ForegroundColor Red
    return
}
function _create_RegKey_if_not_exists($key_path) {
    $key = Get-Item -Path $key_path -ErrorAction SilentlyContinue
    if (!$key) {
        New-Item -Path $key_path -ErrorAction SilentlyContinue -Force | Out-Null
        Write-Verbose "Created key: $key_path"
    }
    else {
        Write-Verbose "Key already exists: $key_path"
    }
}

function disable-mDNS-for-eCDN ($browser) {
    $browser_path = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\$($browser.executable)" -ErrorAction SilentlyContinue).'(Default)'
    Write-Host ""
    if ($browser_path) {
        $browser_version = (Get-Item -Path $browser_path -ErrorAction SilentlyContinue).VersionInfo
        if ($browser_version) {
            Write-Host " $($browser.name) v.$($browser_version.FileVersion) found " -BackgroundColor White -foregroundColor Black # at $browser_path" -ForegroundColor Yellow
        }
        else {
            Write-Host " $($browser.name) purportedly installed but unable to determine version info." -BackgroundColor Red -ForegroundColor White
            Write-Host "Proceeding with adding registry key(s) to disable mDNS for $($browser.name) Browser" -ForegroundColor Yellow
        }

        $Browser_Company, $Browser_Name = $browser.name.Split()
        $Company_KeyPath = Join-Path $HKLM_SW_Policies_Path $Browser_Company
        _create_RegKey_if_not_exists $Company_KeyPath

        $Browser_KeyPath = Join-Path $Company_KeyPath $Browser_Name
        _create_RegKey_if_not_exists $Browser_KeyPath

        $WebRtcLocalIpsAllowedUrls_KeyPath = Join-Path $Browser_KeyPath $browser.webRTCkey
        _create_RegKey_if_not_exists $WebRtcLocalIpsAllowedUrls_KeyPath

        $WebRtcLocalIpsAllowedUrls  = Get-Item -Path $WebRtcLocalIpsAllowedUrls_KeyPath -ErrorAction SilentlyContinue
        if (!$WebRtcLocalIpsAllowedUrls) {
            Write-Host "Failed to create key(s) >_>" -ForegroundColor Red
            return
        }
        $value_names = $WebRtcLocalIpsAllowedUrls.GetValueNames()
        foreach ($value_name in $value_names) {
            $value = $WebRtcLocalIpsAllowedUrls.GetValue($value_name)
            Write-Verbose "Found $($WebRtcLocalIpsAllowedUrls.GetValueKind($value_name)) $value_name with value $value"
            if ($value -eq $eCDN_domain) {
                Write-Host "eCDN domain already exists in $($WebRtcLocalIpsAllowedUrls.GetValueKind($value_name)) $value_name" -ForegroundColor DarkGreen
                return
            }
        }
        # create new value
        $value_name = $value_names.Count + 1
        while ($value_name -in $value_names) {
            $value_name++
        }
        try {
            if ($Browser_Name -eq "Firefox") {
                $value_name = 'media.peerconnection.ice.obfuscate_host_addresses.blocklist'
                
                # check if the value already exists within a list of domains
                if ($values = $WebRtcLocalIpsAllowedUrls.GetValue($value_name)) {
                    $values = $values.split(",").foreach({$_.trim()})
                    if ($values -contains $eCDN_domain) {
                        Write-Host "eCDN domain already exists in $($WebRtcLocalIpsAllowedUrls.GetValueKind($value_name)) $value_name" -ForegroundColor DarkGreen
                        return
                    }
                    $eCDN_domain = $values + $eCDN_domain -join ", "
                }
            }
            New-ItemProperty -Path $WebRtcLocalIpsAllowedUrls_KeyPath -Name $value_name -PropertyType String -Value $eCDN_domain -ErrorAction Stop -Force | Out-Null
            Write-Verbose "eCDN domain added to $($WebRtcLocalIpsAllowedUrls.GetValueKind($value_name)) $value_name"
            Write-Host "Registry key to disable mDNS for $Browser_Name Browser was created" -ForegroundColor Green
        }
        catch {
            Write-Host "Failed to create registry key to disable mDNS for $Browser_Name Browser" -ForegroundColor Red
        }
    }
    else {
        Write-Host " $($browser.name) not found" -BackgroundColor DarkGray -foregroundColor Black
        return
    }
}


foreach ($browser in $browser_list) {
    . disable-mDNS-for-eCDN $browser
}
