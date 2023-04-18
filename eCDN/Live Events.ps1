function LiveEventId {
    Param (
	    [Parameter(Mandatory=$true)]
	    [String]
	    $UrlToDecode
    )
    $UrlToDecode = $UrlToDecode.Trim()

    cls
    Add-Type -AssemblyName System.Web

    $decodedURL = [System.Web.HttpUtility]::UrlDecode($UrlToDecode)
    Write-Host "`nThe decoded url is: `n " $decodedURL "`n"
    $urlTmp =  [System.Uri]$UrlToDecode
    $MeetingID = ""
    $TenantID = ""
    $OrganizerID = ""
    $cnt = 0
    foreach ($IDvalue in $decodedURL.Split("`""))
    {
	    if ($cnt -eq 0)
	    {
		    $MeetingID = $IDvalue.Trim("https://teams.microsoft.com/l/meetup-join/09:meeting_")
		    $MeetingID = $MeetingID.Trim("@thread.v2/0?context={")
	    }
	    if ($cnt -eq 4)
	    {
		    $TenantID = $IDvalue
	    }
	    if ($cnt -eq 8)
	    {
		    $OrganizerID = $IDvalue
	    }
        $cnt++
    }
    #Write-Host "Meeting ID: `n" $MeetingID "`nTenant ID: `n " $TenantID " `nOrganizer ID: `n " $OrganizerID "`n"

    $TLEid = "" | Select-Object MeetingId, TenantId, OrganizerId
    $TLEid.MeetingId = $MeetingID
    $TLEid.TenantId = $TenantID
    $TLEid.OrganizerId = $OrganizerID

    return $TLEid
}

## Token request
$Credential = Get-Credential
$clientId = "12128f48-ec9e-42f0-b203-ea49fb6af367" # This is the build in Teams App Id
$Scopes = @("https://tags.teams.microsoft.com/.default openid profile offline_access")
$ReqTokenBody = @{
    client_id = $clientId #"12128f48-ec9e-42f0-b203-ea49fb6af367"
    client_info = "0"
    scope = [string]::Join(' ', $Scopes)
    grant_type = "password"
    username = $Credential.UserName
    password = $Credential.GetNetworkCredential().Password
}
$Token = Invoke-RestMethod -Uri "https://login.microsoftonline.com/organizations/oauth2/v2.0/token" -Method Post -Body $ReqTokenBody

#get-JWTDetails($Token.access_token)

$today = (Get-Date -Format "yyyy-MM-dd").ToString() + "T00:00:00.000Z"
$ago = (Get-Date).AddMonths((-2)).ToString('yyyy-MM-dd') + "T23:59:59.999Z"

$header = @{
          'Authorization' = "$($Token.token_type) $($Token.access_token)"
          'Content-type'  = "application/json"
}

#$uri = "https://scheduler.teams.microsoft.com/teams/v1/meetings/daterange/c6aae97c-30e4-47d8-98c2-124f9854245f/?startTime=2023-04-01T00:00:00.000Z&endTime=2023-04-07T23:59:59.999Z&organizerId="
$uri = "https://scheduler.teams.microsoft.com/teams/v1/meetings/daterange/c6aae97c-30e4-47d8-98c2-124f9854245f/?startTime=" + $ago + "&endTime=" + $today + "&organizerId="


$body = @{
    "liveEventTypeOfService"="scheduling"
    "liveEventServiceUrl"= $uri
} | ConvertTo-Json

#Get request with Invoke-WebRequest

$url = "https://amer.tags.teams.microsoft.com/api/v1/liveeventservice"
$liveEvents = Invoke-WebRequest -UseBasicParsing -Headers $header -Uri $url -Method Post -Body $body
$liveEvents = $liveEvents.Content | ConvertFrom-Json

$AllLiveEvents = $liveEvents.liveEventServiceData | ConvertFrom-Json
clear
#$TLE = "ZDIxNjVjMjgtYjdlZC00ZjQ5LThmMWEtOWU1ZmIxMTA4NDdl"
#$TLE = Read-Host "Please Enter the Live Event ID"
#clear
Do{
    Do{
        Write-Host "Please Enter the Live Event ID: " -ForegroundColor Cyan -NoNewline
        $TLE = Read-Host
        If($TLE.Length -ne 48){
            Write-Host "Please enter a valid TLE ID" -ForegroundColor Red -BackgroundColor Yellow
            Start-Sleep -Seconds 1
            clear
        }else{break}
    }while ($true)

    $TLEFound = $AllLiveEvents | ?{$_.joinUrl -like "*$($TLE)*"}
    If($TLEFound){
        Write-Host "Teams Live Event Subject: " -ForegroundColor Green -NoNewline
        Write-Host $($TLEFound.Subject) -ForegroundColor DarkRed -BackgroundColor Yellow
        Write-Host "    Organizers: $($TLEFound.participants.organizer.upn)" -ForegroundColor Yellow
        Write-Host "    Producers: $($TLEFound.participants.producers.upn)" -ForegroundColor Yellow
        Write-Host "    Contributors: $($TLEFound.participants.contributors.upn)" -ForegroundColor Yellow
        Write-Host "    Invite Participants Count: $($TLEFound.invitedParticipantsCount)" -ForegroundColor Yellow
    }else{
        Write-Host "No TLE found with that guid in your tenant" -ForegroundColor Red
    }
    $answer = ""
    while("yes","no" -notcontains $answer){
        Write-Host "`n Do you want to find another TLE (Yes/No)? " -ForegroundColor Green -NoNewline
        $answer = read-host
        clear
    }
    If($answer -eq "No"){break}
}while($true)

<#
$testingFunction = LiveEventId -UrlToDecode $AllLiveEvents[0].joinUrl

$AllLiveEvents.Subject
$AllLiveEvents[0].Subject

$AllLiveEvents[0].joinUrl

$AllLiveEvents[0].extensionData

$AllLiveEvents[0].participants

$AllLiveEvents[0].participants.organizer
$AllLiveEvents[0].participants.producers
$AllLiveEvents[0].participants.contributors
$AllLiveEvents[0].participants.attendees
$AllLiveEvents[0].participants.guests
$AllLiveEvents[0].participants.presenters
$AllLiveEvents[0].participants.coOrganizers
$AllLiveEvents[0].participants.registrationParticipants
#>




