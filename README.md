# gundog
gundog - PowerShell based guided hunting in Microsoft 365 Defender

Gundog provides you with guided hunting in Microsoft 365 Defender. Especially (if not only) for Email and 
Endpoint Alerts at the moment.

![alt text](http://100pcloud.com/vid-title.png)

## Functionality

You provide an AlertID (you might received via Email notification) and gundog will then hunt for as much as possible 
associated data. It does not give you the flexibility of advanced hunting like you have in the portal, but it will give you a quick, first overview of  the alert, all associated entities and some enrichment.

All the hunting it does is based on the alert timestamp – so we only care about events shortly before, or after the alert.

It also provides you with PowerShell objects for each entity it hunted for – like $Network for everything it found related to this alert in the Microsoft 365 Defender DeviceNetworkEvents table.

**gundog also comes up with some other features that make your life easier:**

- per default, only the most relevant data is displayed (this is the way)
- it gives you context wherever possible: last AAD Sign-Ins & user’s AAD address
- network connections can be automatically filtered to display more relevant connections only (get rid of connections to Office 365 e.g.)
- network connections are enriched with geo location (country & city)
- in the variables section you can easily adjust most parameters like advanced hunting timeframe of every query
- In addition it searches for IOCs at other services like abuse.ch, urlscan.io or ip-api.com. I ask you to apply for their paid services if you use them commercially.

After first evaluations with gundog, you can continue in the portal to dig deeper into the rabbit hole.

Feel free to extend gundog and send me pull requests! For the best psychodelic experience, use Windows 
Terminal Dracula theme with gundog. 

## Quick usage
```
mandatory parameters:

- TenantID
- ClientID
- ClientSecret

Optional parameters:

- forgetIncidents

(Background: the first thing gundog is doing is to query all incidents and alerts from the incident API from the last 30 days. These are 
saved to a global variable. If you restart gundog, it will not query all incidents again, unless you set forgetIncidents to true.)
```
## Requirements
Register an new App in AAD and give it the following permission:
How to [register an app](https://docs.microsoft.com/en-us/windows/security/threat-protection/microsoft-defender-atp/exposed-apis-create-app-webapp "Microsoft")

```
Microsoft Graph

- Directory.Read.All
- IdentityRiskEvent.Read.All
- IdentityRiskyUser.Read.All
- SecurityEvents.Read.All
- User.Read

Microsoft Threat Protection

- AdvancedHunting.ReadAll
- Incident.Read.All
- Windows Defender ATP

AdvancedQuery.Read.All

- Alert.Read.All
- File.Read.All
- Ip.Read.All
- Url.Read.All
- User.Read.All
- Vulnerability.Read.All

```
For more information visit: https://emptydc.com/2021/02/25/gundog/


