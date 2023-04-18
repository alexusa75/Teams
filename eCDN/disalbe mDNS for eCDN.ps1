
# Disable mDNS for *.ecdn.microsoft.com for Edge and Chrome

$chormecheck = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe' -ErrorAction SilentlyContinue).'(Default)'

If($chormecheck){
    $chrome = (Get-Item -Path $chormecheck -ErrorAction SilentlyContinue).VersionInfo
}

$Edge = Get-AppxPackage -Name *MicrosoftEdge.* | Foreach Version

#get-psdrive

$paths = @(
    "HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebRtcLocalIpsAllowedUrls",
    "HKLM:\SOFTWARE\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls"
)

#### Edge ####
If($Edge){
    $Edgekey = Get-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue

    If(!$Edgekey){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft" -Name Edge
    }

    $WebRtcLocalIpsAllowedUrls  = Get-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebRtcLocalIpsAllowedUrls" -ErrorAction SilentlyContinue

    If(!$WebRtcLocalIpsAllowedUrls){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name WebRtcLocalIpsAllowedUrls
    }

    $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebRtcLocalIpsAllowedUrls" -Name 1 -ErrorAction SilentlyContinue

    If(!$value){
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge\WebRtcLocalIpsAllowedUrls" -Name "1" -PropertyType "String" -Value "*.ecdn.microsoft.com"
        Write-Host "Registry key to disable mDNS for Edge Browser was created" -ForegroundColor Yellow
    }
}

#### Chrome ####
if($chrome){
    $Chromekey1 = Get-Item -Path "HKLM:\SOFTWARE\Policies\Google" -ErrorAction SilentlyContinue

    If(!$Chromekey1){
        New-Item -Path "HKLM:\SOFTWARE\Policies" -Name Google
    }
    $Chromekey = Get-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue

    If(!$Chromekey){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Google" -Name Chrome
    }

    $WebRtcLocalIpsAllowedUrls  = Get-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls" -ErrorAction SilentlyContinue

    If(!$WebRtcLocalIpsAllowedUrls){
        New-Item -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name WebRtcLocalIpsAllowedUrls
    }

    $value = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls" -Name 1 -ErrorAction SilentlyContinue

    If(!$value){
        New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome\WebRtcLocalIpsAllowedUrls" -Name "1" -PropertyType "String" -Value "*.ecdn.microsoft.com"
        Write-Host "Registry key to disable mDNS for Chrome Browser was created" -ForegroundColor Yellow
    }
}