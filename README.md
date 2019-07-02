# Test-ExchangeServerHealth.ps1
PowerShell script to generate a report of the health of an Exchange Server 2010/2013 environment.

Performs a series of health checks on Exchange servers and DAGs and outputs the results to screen, and optionally to log file, HTML report, and HTML email.

**Please note:** This script has slowly degraded over time as new versions and builds of Exchange have been released. This script is no longer being maintained for bugs, however you are free to fork the project to apply your own bug fixes and improvements to suit your needs.

## Usage

Create an ignorelist.txt file in the same folder as the script to specify any servers, DAGs, or databases you want the script to ignore (eg test/dev servers).

Modify the SMTP settings in the script to send emails to your own address:

```
#...................................
# Modify these Email Settings
#...................................

$smtpsettings = @{
	To =  "administrator@exchangeserverpro.net"
	From = "exchangeserver@exchangeserverpro.net"
	Subject = "$reportemailsubject - $now"
	SmtpServer = "smtp.exchangeserverpro.net"
	}
```

When running the script on non-English servers you can modify the following variables in the script to match your language so that the script does not give errors or incorrect results.

```
#...................................
# Modify these language 
# localization strings.
#...................................

# The server roles must match the role names you see when you run Test-ServiceHealth.
$casrole = "Client Access Server Role"
$htrole = "Hub Transport Server Role"
$mbrole = "Mailbox Server Role"
$umrole = "Unified Messaging Server Role"

# This should match the word for "Success", or the result of a successful Test-MAPIConnectivity test
$success = "Success"
```

For example, a German system would use the following values:

```
# The server roles must match the role names you see when you run Test-ServiceHealth.
$casrole = "Clientzugriffs-Serverrolle"
$htrole = "Hub-Transport-Serverrolle"
$mbrole = "Postfachserverrolle"
$umrole = "Unified Messaging-Serverrolle"

# This should match the word for "Success", or the result of a successful Test-MAPIConnectivity test
$success = "Erfolgreich"
```

## Parameters

- **-Server**, Perform a health check of a single server
- **-ReportMode**, Set to $true to generate a HTML report. A default file name is used if none is specified.
- **-ReportFile**, Allows you to specify a different HTML report file name than the default.
- **-SendEmail**, Sends the HTML report via email using the SMTP configuration within the script.
- **-AlertsOnly**, Only sends the email report if at least one error or warning was detected.
- **-Log**, Writes a log file to help with troubleshooting.

## Examples

`.\Test-ExchangeServerHealth.ps1`

Checks all servers in the organization and outputs the results to the shell window.

`.\Test-ExchangeServerHealth.ps1 -Server HO-EX2010-MB1`

Checks the server HO-EX2010-MB1 and outputs the results to the shell window.

`.\Test-ExchangeServerHealth.ps1 -ReportMode -SendEmail`

Checks all servers in the organization, outputs the results to the shell window, a HTML report, and emails the HTML report to the address configured in the script.

## More Information
http://exchangeserverpro.com/powershell-script-exchange-server-health-check-report

## Credits
Written by: Paul Cunningham

Find me on:

* My Blog:	https://paulcunningham.me
* Twitter:	https://twitter.com/paulcunningham
* LinkedIn:	https://au.linkedin.com/in/cunninghamp/
* Github:	https://github.com/cunninghamp

Check out my [books](https://paulcunningham.me/books/) and [courses](https://paulcunningham.me/training/) to learn more about Office 365 and Exchange Server.

Additional Credits (code contributions and testing):
- [Chris Brown](http://twitter.com/chrisbrownie)
- Ingmar Brückner
- John A. Eppright
- Jonas Borelius
- Thomas Helmdach
- Bruce McKay
- Tony Holdgate
- Ryan
- [@andrewcr7](https://github.com/andrewcr7)
