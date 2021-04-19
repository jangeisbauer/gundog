#Region Parameters
param(
    [Parameter()]
    [bool]$forgetIncidents = $false,    
    [Parameter(Mandatory)]
    [string]$tenantId,
    [Parameter(Mandatory)]
    [string]$clientId,
    [Parameter(Mandatory)]
    [string]$clientSecret
)
#EndRegion
#Region Description
$versionText = "Guided hunting for M365 Defender | Version 0.1.2 (March 2021) | Author: @janvonkirchheim"
# 
# gundog provides you with some guided hunting in Microsoft 365 Defender
# espacially (if not only ;-)) for Email and Endpoint Alerts - with a great focus on 
# the endpoint. 
#
# You type in an alertID (you might received via Email notification) and
# gundog will then hunt for as much as possible associated data. 
# 
# It does not give you the flexibility of advanced hunting like you have
# it in the portal, but it will give you a quick, first overview of 
# the alert and all associated entities. So after first evaluations, 
# you can continue in the portal to dig deeper into the rabbit hole. 
#
# In addition it can search for IOCs at other services like abuse.ch and
# urlscan.io. Feel free to extend gundog and send me pull requests!
#
# For the best psychodelic experience, use Windows Terminal Dracula Theme.
#
# Happy hunting!
#
#EndRegion
#Region Global Variables & Application Prep
$debugOn = $false
$irmTimeout = 240 # Timeout for Invoke-RestMethod which is used for all operations

#Turn associated hunting areas on or off 
$registryOn = $true 
$networkOn = $true 
$processesOn = $true 
$vulnerabilitiesOn = $true
$signinsOn = $false
$officeOn = $true
$riskySignInsOn = $true
$emailsOn = $false

#Number of Events (lines) displayed in overview - keep in mind, you always get all result via $object e.g. $Network
$numberOfEvents = 30

#Select a close geo location for better API performance
#api-us.securitycenter.microsoft.com || api-uk.securitycenter.microsoft.com // not working with localized apis at the moment
$apiGeoLocation = "api.securitycenter.microsoft.com"

#Advanced Hunting TimeStamp Settings || T1 = Time before Alert Timestamp T2 = Time after an Alert Timestamp
$signinsT1 = "-7"
$signinsT1u = "day"  
$signinsT2 = "30"
$signinsT2u = "minute"  

$registryT1 = "-120"
$registryT1u = "minute"
$registryT2 = "10"
$registryT2u = "minute"

$networkT1 = "-240"
$networkT1u = "minute"
$networkT2 = "120"
$networkT2u = "minute"

$processesT1 = "-30"
$processesT1u = "minute"
$processesT2 = "30"
$processesT2u = "minute"

$officeT1 = "-120"
$officeT1u = "minute"
$officeT2 = "220"
$officeT2u = "minute"

$emailsT1 = "-480"
$emailsT1u = "minute"
$emailsT2 = "30"
$emailsT2u = "minute"

# do not display connections to those remote URLs (in DeviceNetworkEvents). Be careful with excluding values here - what you exclude, you will not see ;-)
$notMatchThese = "microsoft\.com$|outlook\.com$|live\.com$|microsoftonline\.com$|skype\.com$|office365\.com$|edgesuite.\.net$|$>digicert\.com$|windows\.net$|doubleclick\.net$|windows\.com$|office\.com$|windowsupdate\.com$" 

#EndRegion 
#Region Logo & App Start 

#to change tenants
$logoColor="green"
[console]::ForegroundColor = $logoColor
if(!$debugOn)
{
    Clear-Host
}
write-host "                                                      	gggggg                  " 
write-host "                                                   gggggg                       "       
write-host "                                             gggggg                             "       
write-host "                                      ggggggg                                   "      
write-host "         %ggggggg              ggggggggg                                        "     
write-host "       gggggggggggg.   %ggggggg  gggg                                           "  
write-host "        ggggggggggg ggggggg     gggg                                            "   
write-host "        ggggggggggggggg        ggggg                                            " 
write-host "         ggggggggggggg          ggggg                                           " 
write-host "    ggggggggggggggggggggggggggggggg%                                            "
write-host "    gggggggggggggggggggggggggggggggg                                            "
write-host "   ggggggggggggggggggggggggggggg                                                "
write-host "    ggggggggggggggggggggg    g                                                  "
write-host "   gggggggggggggggggg      .                                                    "
write-host "    ggggggggggggggggggggg                                                       "
write-host "   gggggggggggggggggggg                                                         "
write-host "    ggggggggggggggggggg                                                         "
write-host "    gggggggggggggggggggg                                                        "
write-host "   *ggggggggggggggggggg                                                         "
write-host "   ggggggggggggggggggggg                                                        "
write-host "   gggggggggggggggggggg%                                                        "
write-host "      gggggggggggggggggg                                                        "
write-host "    ggggggggggggggggggggg                                                       "
write-host "    gggggggggggggggggggggg                                                      "
write-host "   gggggggggggg /ggggggggg                                                      "
write-host "    gggggggggg    ggggggggg                                       ,gggggg       "
write-host "   ggggggggggg     gggggggg                              .  gggggggggggggOggg/  "
write-host "   gggggggggg      gggggggg    %gggggggggggggggggggggggggggggggggggggggggg,*    "
write-host "    gggggggg       gggggggg     gggggggggggggggggggggggggggggggggg              "
write-host "   ggggggggg       gggggggg    gggggggggggggggggggggggggggggggg,                "
write-host "   gggggggg       %gggggggg   ggggggggggg    gggggggggggggggg%                  "
write-host "   ggggggg       ggggggggg   /gggggggggg/        ,ggggggggggg                   "
write-host "  gggggggg       gggggggg   gggg   gggg/              gg/  /gggg                "
write-host " ggggggg          ggggggg ggg      ggg        8I      gg       g                "
write-host "ggggggggg         .gggggggg      ggg          8I     *gg      gg                "
write-host " %gggggg          gggggggggg      gg          8I     *gg                        "
write-host " gggggg            *g/ ggggggg     .g         8I       gggg                     "
write-host "ggggg ,gg  gg      gg   ,ggg ggg.      .gggg.8I    ,ggggg.    ,gggg,gg          "
write-host "dP    Y8I  I8      8I  ,8   8P   8,   dP    Y8I   dP    Y8gggdP    Y8I          "
write-host "i8     ,8I  I8.    .8I  I8   8I   8I  i8     .8I  i8     ,8I i8     .8I         "
write-host "d8     d8I  d8b    d8b  dP   8I   Yb  d8     d8b  d8     d8  d8     d8I         "
write-host  "P Y8888P.8888P..Y88P..Y88P.   8I   .Y8P.Y8888P..Y8P.Y8888P   P.Y8888P.888      "    
write-host  "    .d8I.                                                         d8I          "
write-host  "  .dP-8I                                                       ,dP.8I          "
write-host  " .8    8I                                                      .8   8I         "
write-host  "  I8   8I                                                      I8   8I         "
write-host  "  .8   8I                                                      .8   8I         "   
write-host  "   .Y8P.                                                        .Y8P           "
Write-Host 
[console]::ForegroundColor = "White"
write-host $versionText
Write-Host
$AlertId = Read-Host Type AlertID
if(!$debugOn)
{
    Clear-Host
}
#EndRegion
# Does generic hunting via the Microsoft Defender for Endpoint API, provide KQL
function get-huntingResult {
    [CmdletBinding()]
    param (
        [string]$kql,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://" + $apiGeoLocation 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResult: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }

    $token = $authResponse.access_token
    $url = "https://" + $apiGeoLocation + "/api/advancedqueries/run" 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    $body = ConvertTo-Json -InputObject @{ 'Query' = $kql }
    write-host $topic -ForegroundColor Green
    #Write-host $kql
    try {
        $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body  -verbose -debug -TimeoutSec $irmTimeout
    }
    catch {
        Write-Host "get-huntingResult: failed Invoke-RestMethod ($url)"      -ForegroundColor red
        Write-Host URL: $url
        $error
    }
    return $webResponse.Results
}
# NON-Advanced Hunting API access in Microsoft Defender for Endpoint
function get-DefenderAPIResult {
    [CmdletBinding()]
    param (
        [string]$api,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://" + $apiGeoLocation 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-DefenderAPIResult: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }

    $token = $authResponse.access_token
    $url = "https://" + $apiGeoLocation + "/api" + $api 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor Green
    #Write-host $kql
    try {
        $global:webResponse = Invoke-RestMethod -Method get -Uri $url -Headers $headers -verbose -debug -TimeoutSec $irmTimeout
    }
    catch {
        Write-Host "get-DefenderAPIResult: failed Invoke-RestMethod ($url)"      -ForegroundColor red
        Write-Host URL: $url
        $error
    }
    return $webResponse
}
# Advanced hunting against the Microsoft 365 Defender (MTP) API
function get-huntingResultMTP {
    [CmdletBinding()]
    param (
        [string]$kql,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://api.security.microsoft.com" 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResultMTP: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }
    $token = $authResponse.access_token
    $url = "https://api.security.microsoft.com/api/advancedhunting/run" 
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    $body = ConvertTo-Json -InputObject @{ 'Query' = $kql }
    write-host $topic -ForegroundColor Green
    try {
        $webResponse = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body -verbose -debug -TimeoutSec $irmTimeout #-Proxy "http://127.0.0.1:8888"
    }
    catch {
        $errorOutput = "get-huntingResultMTP: failed Invoke-RestMethod ($url) " + $error
        $errorOutput
    }
    $webResponse.Results
}
# NON-Advanced Hunting calls against Microsoft 365 Defender API, does support paging
function get-APIresultMTP {
    [CmdletBinding()]
    param (
        [string]$api,
        [string]$clientID,
        [string]$clientSecret,
        [string]$tenantId,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $client_id = $clientID
    $client_secret = $clientSecret
    $authBody = [Ordered] @{
        resource =  "https://api.security.microsoft.com" 
        client_id = $client_id
        client_secret = $client_secret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-huntingResultMTP: failed Invoke-RestMethod (Auth)"   -ForegroundColor red
        $error
    }
    $token = $authResponse.access_token
    $url = "https://api.security.microsoft.com/api" +  $api
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor Green
    $result  =  @()
    try {
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -verbose -debug -TimeoutSec $irmTimeout #-Proxy "http://127.0.0.1:8888"
        $result = $response.value

        while ($null -ne $response.'@odata.nextLink'){
            $nextUri = $response.'@odata.nextLink';
            $response  = Invoke-RestMethod -Method Get -Uri $nextUri -Headers $headers -verbose -debug -TimeoutSec $irmTimeout
            $result += $response.value
        }
    }
    catch {
        Write-Host "get-APIresultMTP: failed Invoke-RestMethod ($url)" -ForegroundColor red
        $error
    }
    return $result
}
# checks URL Scan for URL entities from Alert
function get-urlInfo {
    [CmdletBinding()]
    param (
        [string]$url
    )
    $error.Clear()
    # cleanup URL
    try {
        $url = $url.ToLower().Replace("https://","")
        $url = $url.ToLower().Replace("http://","")
        $url = $url.Trim("/")
        if($url.Contains("/"))
        {
            $url = $url.Split("/")[0]
        }
    }
    catch {}
    try {
        $global:urlScanQuery = Invoke-RestMethod -Method get -Uri "https://urlscan.io/api/v1/search/?q=domain:$url" #-verbose -debug #-Proxy "http://127.0.0.1:8888"
        if($urlScanQuery.results.length -ne 0)
        {
            $global:urlScanResultUrl = ($urlScanQuery.results | Sort-Object indexedAt -Descending | Select-Object -Last 1).result
        }
    }
    catch {
        Write-Host "get-URLinfo: failed Invoke-RestMethod (UrlScan)" -ForegroundColor red
        $error
    }
    if($urlScanResultUrl -ne "" -and $null -ne $urlScanResultUrl)
    {
        try {
            $global:urlScan = Invoke-RestMethod -Method get -Uri $urlScanResultUrl #-verbose -debug #-Proxy "http://127.0.0.1:8888"
        }
        catch {
            Write-Host "get-URLinfo: failed Invoke-RestMethod ($url)" -ForegroundColor red
            $error
        }
    }
}
# common quieries against MS Graph
function get-graphResponse{
    [CmdletBinding()]
    param (
        [string]$graphQuery,
        [string]$tenantId,
        [string]$clientid,
        [string]$clientsecret,
        [string]$topic
    )
    $error.Clear()
    $oAuthUri = "https://login.microsoftonline.com/" + $tenantId + "/oauth2/token"
    $authBody = [Ordered] @{
        resource = "https://graph.microsoft.com" 
        client_id = $clientid
        client_secret = $clientsecret
        grant_type = "client_credentials"
    }
    try {
        $authResponse = Invoke-RestMethod -Method Post -Uri $oAuthUri -Body $authBody -ErrorAction Stop
    }
    catch {
        Write-Host "get-graphResponse: failed Invoke-RestMethod (auth)" -ForegroundColor red
        $error
    }

    $token = $authResponse.access_token
    $url = "https://graph.microsoft.com$graphQuery"
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
        Authorization = "Bearer $token" 
    }
    write-host $topic -ForegroundColor green
    try {
        $webResponse = Invoke-RestMethod -Method Get -Uri $url -Headers $headers -ErrorAction Stop
        $webResponse
    }
    catch {
        Write-Host "get-graphResponse: failed Invoke-RestMethod ($url)" -ForegroundColor red
        $error
    }

}
# rest call without authentication, provide full url
function get-simpleRestCall{
    [CmdletBinding()]
    param (
        [string]$url,
        [string]$body,
        [string]$topic,
        [string]$method
    )
    $error.Clear()
    $headers = @{ 
        'Content-Type' = 'application/json'
        Accept = 'application/json'
    }
    write-host $topic -ForegroundColor green
    try {
        $webResponse = Invoke-RestMethod -Method $method -Uri $url -body $body -Headers $headers -ErrorAction Stop
        $webResponse
    }
    catch {
        Write-Host "get-simpleRestCall: failed Invoke-RestMethod ($topic)" -ForegroundColor red
        $error
    } 
}
#gets fileInfo from abuse.ch, provide file hash
function get-fileInfo {
    [CmdletBinding()]
    param (
        [string]$fileHash
    )
    $error.Clear()
    try {
        #check abuse.ch
        $global:abuseFileResponse = Invoke-RestMethod -Method POST -Uri "https://mb-api.abuse.ch/api/v1/" -body "query=get_info&hash=$fileHash" -ErrorAction Stop
        $global:abuseFileData = $abuseFileResponse.data
        $global:abuseFileStatus = $abuseFileResponse.query_status
        }
    catch {
        Write-Host "get-fileInfo: failed Invoke-RestMethod (abuse)" -ForegroundColor red
        $error
    }    
}
# this is mainly called when script is restarted, after it first run, we want the global vars still available to work with,
# but then, when script is re-run, we need to clear them upfront
function clear-allVars {
        # variable cleanup
        try { Remove-Variable plainalert -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable device -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable user -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable registry -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable network -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable processes -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable vulnerabilities -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable signins -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable office -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable emails -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable alert -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable upn -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable emailAddress -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable riskySignIns -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable logons -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable allAlerts -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable AccountSid -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable AadDeviceId -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable fileHash -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable filesApiInfo -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable filesApiStats -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable DeviceId -Scope global -ErrorAction SilentlyContinue } catch {}
        try { Remove-Variable geoIPInfo -Scope global -ErrorAction SilentlyContinue } catch {}
}
# Main function to get all the data for the Alert Report
function get-alertData {
    [CmdletBinding()]
    param (
        [string]$AlertId,
        [string]$tenantId,
        [string]$clientSecret,
        [string]$clientId
    )
    # clear all vars
    clear-allVars
    $error.Clear()
    #$allIncidents is not cleared from last run. So, we take the results and re-use them if they exist
    if($allIncidents.count -eq 0 -or $forgetIncidents)
    {
        if($AlertId -ne "")
        {
            try {  
                #allIncidents is empty, get all incidents from the last 30 days - don't change this to +30days, all other advanced hunting queries can only do 30days        
                $Today = Get-date -Format "yyyy-MM-dd"
                $StartDateAllIncidents = (get-date($Today)).AddDays(-30)
                $StartDateAllIncidentsF = Get-Date $StartDateAllIncidents -Format "yyyy-MM-dd"
                $tempUrl="/incidents?`$filter=createdTime%20gt%20" + $StartDateAllIncidentsF
                $global:allIncidents = get-APIresultMTP -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all incidents/alerts" -api $tempUrl
                $global:plainalert = $allIncidents.alerts | Where-Object {$_.alertid -eq $AlertId}
            }
            catch {
                Write-Host "Error: Query for AlertId failed! This is not your day, Mando." -ForegroundColor red
                $error
            }
        }
    }
    else {
        $global:plainalert = $allIncidents.alerts | Where-Object {$_.alertid -eq $AlertId}
    }
    if($error.count -eq 0 -and $null -ne $plainalert)
    {
        #build the $alert object
        $global:alert = new-object psobject
        $alert | add-member Noteproperty Timestamp ($plainalert.creationTime.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AlertId ($plainalert.alertId.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Title ($plainalert.title.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Category ($plainalert.Category.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty ServiceSource ($plainalert.ServiceSource.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty DetectionSource ($plainalert.DetectionSource.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Entities ($plainalert.Entities.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty DeviceName ($plainalert.devices.deviceDnsName.Where({$_ -ne ""}) | Select-Object -Unique)

        #if the alert has an assigned device ID
        if($plainalert.Devices.mdatpDeviceId -ne "")
        {
            $alert | add-member Noteproperty DeviceId ($plainalert.Devices.mdatpDeviceId.tolower().Where({$_ -ne ""}) | Select-Object -Unique)
        } #if not check entities for device IDs
        else {
            if($plainalert.entities.deviceid -ne "")
            {
                $alert | add-member Noteproperty DeviceId ($plainalert.entities.deviceid.tolower().Where({$_ -ne ""}) | Select-Object -Unique)
            }
        }
        #User Object from Entities
        $alert | add-member Noteproperty AccountName ($plainalert.entities.AccountName.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AccountDomain ($plainalert.entities.DomainName.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty AccountSid ($plainalert.entities.UserSid.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty FileName ($plainalert.entities.FileName.Where({$_ -ne ""}))
        $alert | add-member Noteproperty SHA1 ($plainalert.entities.sha1.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty SHA256 ($plainalert.entities.sha256.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty Folderpath ($plainalert.entities.filepath.Where({$_ -ne ""}))
        $alert | add-member Noteproperty Urls ($plainalert.entities.url.Where({$_ -ne ""}) | Select-Object -Unique)      
        $alert | add-member Noteproperty EmailSubject ($plainalert.entities.subject.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty EmailSender ($plainalert.entities.sender.Where({$_ -ne ""}) | Select-Object -Unique)
        $alert | add-member Noteproperty EmailDeliveryAction ($plainalert.entities.DeliveryAction.Where({$_ -ne ""}) | Select-Object -Unique)

        #Build the device object
        $global:Device = new-object psobject
        $Device | add-member Noteproperty Name ($alert.DeviceName)
        $Device | add-member Noteproperty Platform $plainalert.Devices.osPlatform
        $Device | add-member Noteproperty Build $plainalert.Devices.osBuild
        $Device | add-member Noteproperty HealthStatus $plainalert.Devices.healthStatus
        $Device | add-member Noteproperty RiskScore $plainalert.Devices.riskScore
        $Device | add-member Noteproperty FirstSeen $plainalert.Devices.firstSeen
        $Device | add-member Noteproperty MachineTags $plainalert.Devices.tags

        #explicit vars needed for advanced hunting
        $DeviceId = $alert.DeviceId
        $global:Timestamp = $alert.Timestamp
        $AccountSid = $alert.AccountSid

        #try to get more identity info via advanced hunting in IdentityInfo table via user SID
        if($null -ne $AccountSid)
        {
            $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where CloudSid =~ '$AccountSid' or OnPremSid =~ '$AccountSid' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
        }
        else { #if there is no SID, we make a REST call and check for logonusers of the device
            $tempUrl="/machines/$deviceid/logonusers"
            $global:Account=get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting device logons" -api $tempUrl
            $global:AccountName = $Account.value.accountname
            try {
                if($AccountName.GetType().Name -eq "Object[]") #lets see if we have to deal with multiple logon accounts or one
                {
                    $global:AccountName = ($AccountName | Group-Object | Sort-Object count -Descending)[0].name #take the first account
                    $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                    if($null -eq $plainIdentity)
                    {
                        $global:AccountName = ($AccountName | Group-Object | Sort-Object count -Descending)[1].name #take the second account
                        $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                    }
                }
                else {
                    $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
                }
            }
            catch {
                $global:plainIdentity = get-huntingResultMTP -kql "IdentityInfo | where AccountName =~ '$AccountName' | take 10" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting identity info"
            }         
        }

        #now take the IdentityInfo results and build a user object
        $global:user = new-object psobject
        $user | add-member Noteproperty AccountUpn ($plainIdentity.AccountUpn.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty Department ($plainIdentity.Department.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty JobTitle ($plainIdentity.JobTitle.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty AccountName ($plainIdentity.AccountName.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty AccountDomain ($plainIdentity.AccountDomain.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty EmailAddress ($plainIdentity.EmailAddress.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty City ($plainIdentity.City.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty Country ($plainIdentity.Country.Where({$_ -ne ""}) | Select-Object -Unique)
        $user | add-member Noteproperty IsAccountEnabled ($plainIdentity.IsAccountEnabled.Where({$_ -ne ""}) | Select-Object -Unique)

        #create some explicit vars we need for advanced hunting
        $upn = $user.AccountUpn
        $emailAddress = $user.EmailAddress

        #associated hunting - main advanced hunting action starts here
        #lets see if we use sha1 or sha256 (prefer sha1 over sha256) 
        if($null -ne $alert.sha1) 
        {
            $global:fileHash = $alert.sha1
        } 
        else 
        {
            if($null -ne $alert.sha256)
            {
                $global:fileHash = $alert.sha256
            }
        }
        #if we have a deviceID, hunt the: registry, network, processes and vulnerabilities (last one not via advanced hunting but API)
        if($null -ne $DeviceId -and $DeviceId -ne "")
        {
            if($registryOn) { $global:registry = get-huntingResult -kql "DeviceRegistryEvents  | where DeviceId =~ '$DeviceId' | where Timestamp  between (datetime_add('$registryT1u', $registryT1, datetime($Timestamp))..datetime_add('$registryT2u', $registryT2, datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting registry info" }
            if($networkOn) { 
                $global:network = get-huntingResult -kql "DeviceNetworkEvents | where DeviceId == '$DeviceId' | where Timestamp  between (datetime_add('$networkT1u',$networkT1,datetime($Timestamp))..datetime_add('$networkT2u', $networkT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting network info" 
                if($numberOfEvents -le 100)
                {
                    $numberOfIps = $numberOfEvents
                }
                else {
                    $numberOfIps = 100
                }
                $body = $network.Remoteip.Where({$_ -ne ""}) | Select-Object -Unique | Select-Object -Last $numberOfIps
                $body = $body | ForEach-Object {'"' + $_ + '",'}
                $finalBody = "[" + (-join $body).trimend(",") + "]"
                $global:ipGeoInfo = get-simpleRestCall -url "http://ip-api.com/batch" -body $finalBody -method "POST" -topic "... getting geo-IP info" 
            }
            if($processesOn) { $global:processes = get-huntingResult -kql "DeviceProcessEvents | where DeviceId =~ '$DeviceId' | where Timestamp  between (datetime_add('$processesT1u', $processesT1,datetime($Timestamp))..datetime_add('$processesT2u', $processesT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting processes info" }

            if($vulnerabilitiesOn) { 
                $vulnUrl="/vulnerabilities/machinesVulnerabilities?`$filter=machineId eq '$deviceId'"
                $rawVulnerabilities =  get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all vulnerability info" -api $vulnUrl 
                $global:vulnerabilities = $rawVulnerabilities.value
            } 
        }
        #getting fileinfo and filestats from MD API
        if($null -ne $fileHash)
        {
            if($fileHash.GetType().Name -eq "Object[]")
            {
                $filesApiInfo = [System.Collections.ArrayList]@()
                $filesApiStats = [System.Collections.ArrayList]@()
                foreach ($fh in $fileHash) {
                    $fileInfoUrl="/files/" + $fh
                    $fileStatsUrl="/files/" + $fh + "/stats?lookBackHours=48"
                    $filesApiStatsTemp = New-Object psobject
                    $filesApiInfoTemp = New-Object psobject
                    $filesApiInfoTemp = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file info" -api $fileInfoUrl
                    $filesApiStatsTemp = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file statistics" -api $fileStatsUrl
                    if($null -ne $filesApiStatsTemp -and $filesApiStatsTemp -ne "")
                    {
                        $filesApiStats.add($filesApiStatsTemp)
                    }
                    if($null -ne $filesApiInfoTemp -and $filesApiInfoTemp -ne "")
                    { 
                        $filesApiInfo.add($filesApiInfoTemp)
                    }
                }
            }
            else {
                $fileInfoUrl="/files/" + $fileHash
                $fileStatsUrl="/files/" + $fileHash + "/stats?lookBackHours=48"
                $global:filesApiInfo = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file info" -api $fileInfoUrl
                $global:filesApiStats = get-DefenderAPIResult -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret -topic "... getting all file statistics" -api $fileStatsUrl
            }
        }
        #if we have a user UPN, we hunt for sign-ins to AAD, Office-files in MCAS and risky sign-ins (the last via direct api, not advanced hunting)
        if($null -ne $upn -and $upn -ne "")
        {
            if($signinsOn -and $null -eq $signins) { $global:signins = get-huntingResultMTP -kql "AADSignInEventsBeta | where AccountUpn =~ '$upn' | where Timestamp  between (datetime_add('$signinsT1u', $signinsT1,datetime($Timestamp))..datetime_add('$signinsT2u', $signinsT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting AAD sign-in info" }
            if($officeOn) { $global:office = get-huntingResultMTP -kql "AppFileEvents | where AccountUpn =~ '$upn' | where Timestamp  between (datetime_add('$officeT1u', $officeT1,datetime($Timestamp))..datetime_add('$officeT2u', $officeT2,datetime($Timestamp)))" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting Office (MCAS) info" }
            if($riskySignInsOn) { $global:riskySignIns = get-graphResponse -graphQuery "/beta/riskDetections?`$filter=userPrincipalName eq '$upn'" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting risky sign-ins" }
        }
        #if we have a user email address, we also hunt for the last incoming and outgoing mail from and to the user mailbox
        if($null -ne $emailAddress -and $emailAddress -ne "")
        {
            if($emailsOn) { $global:emails = get-huntingResultMTP -kql "EmailEvents | where RecipientEmailAddress =~ '$emailAddress' or SenderFromAddress =~ '$emailAddress' | where Timestamp  between (datetime_add('$emailsT1u', $emailsT1,datetime($Timestamp))..datetime_add('$emailsT2u', $emailsT2,datetime($Timestamp))) | join kind=leftouter EmailUrlInfo on NetworkMessageId | join kind=leftouter EmailAttachmentInfo on NetworkMessageId" -tenantId $tenantId -clientID $clientId -clientSecret $clientSecret -topic "... getting email info" }
        }
    }
    else {
        Write-Host "Error: Query for AlertId failed! This is the way, too!"  -ForegroundColor red
    }
}
#Main function to PRESENT the data
function get-alertDataResults {
    if(!$debugOn)
    {
        Clear-Host
    }
    if($null -ne $alert)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor red
        $tempAlertTitle = "[" + $plainalert.severity + "] " + $alert.Title   
        Write-Host "$tempAlertTitle (more info via `$alert)"  -ForegroundColor red       
        $alertTime = get-date($alert.Timestamp)
        Write-Host $alertTime
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor red
        Write-Host
        Write-Host "Category:" $alert.category "| Detection Source:" $alert.DetectionSource "| Investigation: " $plainalert.investigationState "| Status: " $plainalert.status
        Write-Host 
    }
    if($null -ne $plainalert)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor darkyellow
        $incidentName = $Incident.incidentName 
        Write-Host "Associated Incident: $incidentName (more info via `$Incident)"  -ForegroundColor darkyellow      
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor darkyellow
        Write-Host
        $global:Incident = $allIncidents | Where-Object{$_.incidentid -eq $plainalert.incidentId}
        Write-Host "Incident ID:" $Incident.incidentId " | Incident Severity:" $Incident.Severity  
        Write-Host
        if($Incident.alerts.count -gt 1)
        {
            Write-Host "Other Alerts in this Incident:" -ForegroundColor darkyellow
            Write-Host
            foreach ($incidentAlert in $Incident.alerts) {
                if($incidentAlert.alertId -ne $plainalert.alertId)
                {
                    Write-Host "Alert Name:" $incidentAlert.title
                    Write-Host "AlertID:" $incidentAlert.alertID
                    Write-Host "Severity:" $incidentAlert.severity
                    Write-Host "Service Source:" $incidentAlert.serviceSource
                    Write-Host "Creation Time:" $incidentAlert.creationTime
                    Write-Host "Status:" $incidentAlert.status
                    write-Host "Classification:" $incidentAlert.classification
                    write-Host "Assigned To:" $incidentAlert.assignedTo
                    Write-Host
                }
            }
        }
        else {
            Write-Host "The alert is the only alert in this incident."
            Write-Host 
        }
    }
    if($null -ne $alert.EmailSubject)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Email-Alert                                                                                     (more info via `$alert)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "EmailSubject:" $alert.EmailSubject
        Write-Host "EmailP1Sender:" $alert.EmailP1Sender 
        Write-Host "EmailP2Sender:" $alert.EmailP2Sender
        Write-Host "EmailSenderIP:" $alert.EmailSenderIP 
        Write-Host "EmailThreats:" $alert.EmailThreats 
        Write-Host "EmailThreatIntelligence:" $alert.EmailThreatIntelligence 
        Write-Host "EmailDeliveryAction:" $alert.EmailDeliveryAction 
        Write-Host "EmailDeliveryLocation:" $alert.EmailDeliveryLocation 
        Write-Host
    }
    if($null -ne $alert.Entities.ProcessCommandLine)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Process Alert                                                                                   (more info via `$alert)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "File Name:" $alert.Entities.fileName
        Write-Host "File Path:" $alert.Entities.filePath
        Write-Host "Process Command Line:" $alert.Entities.ProcessCommandLine 
        Write-Host
    }
    if($null -ne $alert.filename -or $null -ne $alert.sha256 -or $null -ne $alert.folderpath -or $null -ne $alert.sha1)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Files                                                                (more info via `$filesApiInfo and `$filesApiStats)"  -ForegroundColor green   
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "FileName:" $alert.filename 
        Write-Host "Folderpath:" $alert.folderpath 
        Write-Host "SHA1:" $alert.sha1
        Write-Host "SHA256:" $alert.sha256 
        Write-Host
        if($null -ne $filesApiInfo)
        {
            if($filesApiInfo.GetType().Name -eq "Object[]")
            {
                foreach ($fi in $filesApiInfo) {
                    Write-Host Global Prevalence: $fi.globalPrevalence
                    Write-Host Global First Observed: $fi.globalFirstObserved
                    Write-Host File Size: $fi.size
                    Write-Host File Product Name: $fi.fileProductName
                    Write-Host Signer: $fi.signer
                    Write-Host Issuer: $fi.issuer
                    Write-Host Is Valid Cert: $fi.isValidCertificate
                    Write-Host
                }
            }
            else {
                Write-Host Global Prevalence: $filesApiInfo.globalPrevalence
                Write-Host Global First Observed: $filesApiInfo.globalFirstObserved
                Write-Host File Size: $filesApiInfo.size
                Write-Host File Product Name: $filesApiInfo.fileProductName
                Write-Host Signer: $filesApiInfo.signer
                Write-Host Issuer: $filesApiInfo.issuer
                Write-Host Is Valid Cert: $filesApiInfo.isValidCertificate
                Write-Host
            }
        }
        if($null -ne $filesApiStats)
        {
            if($filesApiStats.GetType().Name -eq "Object[]")
            {
                foreach ($fs in $filesApiStats) {
                    Write-Host Org Prevalence: $fs.orgPrevalence
                    Write-Host Org First Obeserved: $fs.orgFirstSeen
                    Write-Host
                }
            }
            else {
                Write-Host Org Prevalence: $filesApiStats.orgPrevalence
                Write-Host Org First Obeserved: $filesApiStats.orgFirstSeen
                Write-Host
            }
        }
        if($null -ne $fileHash)
        {
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host "abuse.ch File Analysis                                            (more info via `$abuseFileData & `$abuseFileResponse)" -ForegroundColor green   
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            # check abuse
            if($fileHash.GetType().Name -eq "Object[]")
            {
                foreach ($fh in $fileHash) {
                    get-fileInfo -fileHash $fh
                    if($null -ne $abuseFileData -and $abuseFileData -ne "")
                    {
                        Write-Host $fh -ForegroundColor Yellow
                        write-host $abuseFileData 
                    }
                    else {
                        Write-Host $fh -ForegroundColor Yellow
                        write-host $abuseFileStatus
                    }
                }
            }
            else {
                get-fileInfo -fileHash $fileHash
                    if($null -ne $abuseFileData -and $abuseFileData -ne "")
                    {
                        Write-Host $fileHash -ForegroundColor Yellow
                        write-host $abuseFileData
                    }
                    else {
                        Write-Host $fileHash -ForegroundColor Yellow
                        write-host $abuseFileStatus
                    }
            }
            Remove-Variable fileHash -ErrorAction SilentlyContinue
            Write-Host
        }
    }

    if($null -ne $alert.Remoteurl -or $null -ne $alert.urls)
    {
        if($alert.urls -ne "about:internet")
        {
            if($null -ne $alert.Remoteurl) {$url = $alert.Remoteurl}
            if($null -ne $alert.urls) {$url = $alert.urls}
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host "URLs                                                                     (more info via `$urlScan & `$urlScanResultUrl)" -ForegroundColor green
            Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
            Write-Host $alert.url
            Write-Host
            
            if($url.GetType().Name -eq "Object[]")
            {
                foreach ($u in $url) {
                    get-urlInfo -url $u
                    if($null -ne $urlScan -and $urlScan -ne "")
                    {
                        Write-Host $u -ForegroundColor Yellow
                        write-host $urlScanResult 
                        if($null -ne $urlScan.verdicts.overall)
                        {
                            Write-Host Malicious: $urlScan.verdicts.overall.malicious
                            $ipsTemp = $urlScan.lists.ips | Select-Object -First 10
                            Write-Host IPs: $ipsTemp
                            $countryTemp = $urlScan.lists.countries | Select-Object -First 10
                            Write-Host Countries: $countryTemp
                            $cityTemp = $urlScan.page.city | Select-Object -First 10
                            Write-Host City: $cityTemp
                            $domainsTemp = $urlScan.lists.Domains | Select-Object -First 10
                            Write-Host Domains: $domainsTemp
                            $serverTemp = $urlScan.lists.servers | Select-Object -First 10
                            Write-Host Server: $serverTemp
                            $certsTemp = $urlScan.lists.certificates | Select-Object -First 10
                            Write-Host Certificates: $certsTemp
                            write-host
                        }
                    }
                    else {
                        Write-Host $u -ForegroundColor Yellow
                        write-host "No results from URLScan.io"
                    }
                }
            }else 
            {
                get-urlInfo -url $url
                if($null -ne $urlScan -and $urlScan -ne "")
                {
                    Write-Host $url -ForegroundColor Yellow
                    write-host $urlScanResult
                    if($null -ne $urlScan.verdicts.overall)
                    {
                        Write-Host Malicious: $urlScan.verdicts.overall.malicious
                        $ipsTemp = $urlScan.lists.ips | Select-Object -First 10
                        Write-Host IPs: $ipsTemp
                        $countryTemp = $urlScan.lists.countries | Select-Object -First 10
                        Write-Host Countries: $countryTemp
                        $cityTemp = $urlScan.page.city | Select-Object -First 10
                        Write-Host City: $cityTemp
                        $domainsTemp = $urlScan.lists.Domains | Select-Object -First 10
                        Write-Host Domains: $domainsTemp
                        $serverTemp = $urlScan.lists.servers | Select-Object -First 10
                        Write-Host Server: $serverTemp
                        $certsTemp = $urlScan.lists.certificates | Select-Object -First 10
                        Write-Host Certificates: $certsTemp
                        write-host
                    }
                }
                else {
                    Write-Host $url -ForegroundColor Yellow
                    write-host "No results from URLScan.io"
                }
            }
            Remove-Variable url -ErrorAction SilentlyContinue
            Remove-Variable urlScan -ErrorAction SilentlyContinue
            Remove-Variable urlScanResult -ErrorAction SilentlyContinue
            Write-Host
        }
    }
    if($null -ne $device)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "Device                                                                                         (more info via `$Device)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $device  | Out-Host
    }
    if($null -ne $user)
    {
        Write-Host
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "User                                                                                             (more info via `$User)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $user  | Out-Host
    }
    if($null -ne $riskySignIns)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Risky SignIns                                                                            (more info via `$riskySignIns)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $riskySignIns.value | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.activityDateTime)}}, riskType, riskEvent, riskLevel, @{Name="City";expression={$_.location.city}}, @{Name="State";expression={$_.location.state}}, @{Name="Country";expression={$_.location.countryorregion}} | Out-Host
        Write-Host
        if($riskySignIns.value.Count -eq 0)
        {
            $AccountName = $user.accountname
            Write-Host "No Risky SignIns for" $AccountName
            Write-Host
        }
    }
    if($null -ne $network)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Network                                                                                       (more info via `$Network)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $network | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Where-Object{$_.remoteurl -ne "" -and $_.remoteurl -notmatch $notMatchThese} | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}},InitiatingProcessFileName, @{Name="Country";expression={($ipGeoInfo -match $_.RemoteIP).Country}},@{Name="City";expression={($ipGeoInfo -match $_.RemoteIP).City}}, RemoteIP, RemotePort, RemoteUrl | Out-Host
    }
    if($null -ne $processes)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Processes                                                                                   (more info via `$Processes)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $processes | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, ActionType, FolderPath, ProcessCommandLine, InitiatingProcessAccountName | Out-Host
    }
    if($null -ne $vulnerabilities)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Vulnerabilities                                                                       (more info via `$vulnerabilities)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $criticalVuln=$vulnerabilities | Where-Object {$_.severity -eq "Critical"} | Format-Table cveId, productName, ProductVendor, ProductVersion, severity | Out-Host
        $criticalVuln
        Write-Host
        if($criticalVuln.Count -eq 0)
        {
            $deviceName = $device.name 
            Write-Host "No critical vulnerabilities on $deviceName"
            Write-Host
        }
    }
    if($null -ne $signins)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "SignIns                                                                                       (more info via `$signins)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        Write-Host "User City:" $user.city "User Country:" $user.country -ForegroundColor yellow
        $signins | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, Application, LogonType, AccountUpn, DeviceName, Country, City, IPAddress  | Out-Host
    }
    if($null -ne $emails)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Emails                                                                                         (more info via `$emails)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $emails | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, SenderFromAddress, RecipientEmailAddress, Subject, Url, FileName  | Out-Host
    }
    if($null -ne $office)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Office                                                                                         (more info via `$Office)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $office | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, Application, FileName, DeviceName, ISP | Out-Host
    }
    if($null -ne $allalerts)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "All Alerts                                                                                  (more info via `$allalerts)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $allIncidents.alerts | Where-Object{$_.devices.devicednsname -eq $alert.devicename -or $_.entities.accountname -eq $alert.accountname} | Format-Table @{Name="Time";expression={get-date($_.creationTime)}}, Title, Severity, status, DetectionSource | out-host
    }
    if($null -ne $registry)
    {
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        write-host "Registry                                                                                     (more info via `$Registry)" -ForegroundColor green
        Write-Host ------------------------------------------------------------------------------------------------------------------------- -ForegroundColor green
        $registry | Select-Object -Last $numberOfEvents -ErrorAction SilentlyContinue | Where-Object {$_.RegistryValueName -ne ""} | Sort-Object Timestamp -Descending | Format-Table @{Name="Time";expression={get-date($_.TimeStamp)}}, RegKey, RegistryValueName, RegistryValueData, InitiatingProcessCommandLine | Out-Host
    }
}
#Region Output
write-host Hunting ... -ForegroundColor red
get-alertData -AlertId $AlertId -tenantId $tenantId -clientID $clientID -clientSecret $clientSecret
get-alertDataResults

if($null -eq $alert)
{
    write-host "Sorry Mando, we couldn't get any response for the Alert ID you provided:" $AlertId  -ForegroundColor red
}
#EndRegion 
