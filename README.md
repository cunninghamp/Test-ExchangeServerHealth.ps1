# Test-ExchangeServerHealth.ps1
PowerShell script to generate a report of the health of an Exchange Server 2010/2013 environment.

Performs a series of health checks on Exchange servers and DAGs and outputs the results to screen, and optionally to log file, HTML report, and HTML email.

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

* My Blog:	http://paulcunningham.me
* Twitter:	https://twitter.com/paulcunningham
* LinkedIn:	http://au.linkedin.com/in/cunninghamp/
* Github:	https://github.com/cunninghamp

For more Exchange Server tips, tricks and news
check out Exchange Server Pro.

* Website:	http://exchangeserverpro.com
* Twitter:	http://twitter.com/exchservpro

Additional Credits (code contributions and testing):
- Chris Brown, http://twitter.com/chrisbrownie
- Ingmar Brückner
- John A. Eppright
- Jonas Borelius
- Thomas Helmdach
- Bruce McKay
- Tony Holdgate
- Ryan
- Przemyslaw Obiala, Wojciech Sciesinski
