<#
.SYNOPSIS
Test-ExchangeServerHealth.ps1 - Exchange Server Health Check Script.

.DESCRIPTION 
Performs a series of health checks on Exchange servers and DAGs
and outputs the results to screen, and optionally to log file, HTML report,
and HTML email.

Use the ignorelist.txt file to specify any servers, DAGs, or databases you
want the script to ignore (eg test/dev servers).

.OUTPUTS
Results are output to screen, as well as optional log file, HTML report, and HTML email

.PARAMETER Server
Perform a health check of a single server

.PARAMETER ReportMode
Set to $true to generate a HTML report. A default file name is used if none is specified.

.PARAMETER ReportFile
Allows you to specify a different HTML report file name than the default.

.PARAMETER SendEmail
Sends the HTML report via email using the SMTP configuration within the script.

.PARAMETER AlertsOnly
Only sends the email report if at least one error or warning was detected.

.PARAMETER Log
Writes a log file to help with troubleshooting.

.EXAMPLE
.\Test-ExchangeServerHealth.ps1
Checks all servers in the organization and outputs the results to the shell window.

.EXAMPLE
.\Test-ExchangeServerHealth.ps1 -Server HO-EX2010-MB1
Checks the server HO-EX2010-MB1 and outputs the results to the shell window.

.EXAMPLE
.\Test-ExchangeServerHealth.ps1 -ReportMode -SendEmail
Checks all servers in the organization, outputs the results to the shell window, a HTML report, and
emails the HTML report to the address configured in the script.

.LINK
http://exchangeserverpro.com/powershell-script-health-check-report-exchange-2010

.NOTES
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
- Rob Silver
- Przemyslaw Obiala, Wojciech Sciesinski

Change Log
V1.00, 5/07/2012 - Initial version
V1.01, 5/08/2012 - Minor bug fixes and removed Edge Tranport checks
V1.02, 5/05/2013 - A lot of bug fixes, updated SMTP to use Send-MailMessage, added DAG health check.
V1.03, 4/08/2013 - Minor bug fixes
V1.04, 19/08/2013 - Added Exchange 2013 compatibility, added option to output a log file, converted many
					sections of code to use pre-defined strings, fixed -AlertsOnly parameter, improved summary 
					sections of report to be more readable and include DAG summary
V1.05, 23/08/2013 - Added workaround for Test-ServiceHealth error for Exchange 2013 CAS-only servers
V1.06, 28/10/2013 - Added workaround for Test-Mailflow error for Exchange 2013 Mailbox servers.
                       - Added workaround for Exchange 2013 mail test.
                       - Added localization strings for service health check errors for non-English systems.
                       - Fixed an uptime calculation bug for some regional settings.
                       - Excluded recovery databases from active database calculation.
                       - Fixed bug where high transport queues would not count as an alert.
                       - Fixed error thrown when Site attribute can't be found for Exchange 2003 servers.
                       - Fixed bug causing Exchange 2003 servers to be added to the report twice.
V1.07, 24/11/2013 - Fixed bug where disabled content indexes were counted as failed.
V1.08, 29/06/2014 - Fixed bug with DAG reporting in mixed Exchange 2010/2013 orgs.
V1.09, 6/07/2014 - Fixed bug with DAG member replication health reporting for mixed Exchange 2010/2013 orgs.
V1.10, 19/08/2014 - Fixed bug with E14 replication health not testing correct server.
V1.11, 11/02/2015 - Added queue length to Transport queue result in report.
V1.12, 5/03/2015 - Fixed bug with color-coding in report for Transport Queue length.
V1.13, 7/03/2015 - Fixed bug with incorrect function name used sometimes when trying to call Write-LogFile
V1.14, 21/5/2015 - Fixed bug with color-coding in report for Transport Queue length on CAS-only Exchange 2013 servers.
V1.15, 18/11/2015 - Fixed bug with Exchange 2016 version detection.
V1.16, 03/12/2015 - Added checks for clients connections statistics per CAS servers
#>

#requires -version 2

[CmdletBinding()]
param (
	[Parameter( Mandatory=$false)]
	[string]$Server,

	[Parameter( Mandatory=$false)]
	[string]$ServerList,	
	
	[Parameter( Mandatory=$false)]
	[string]$ReportFile="exchangeserverhealth.html",

	[Parameter( Mandatory=$false)]
	[switch]$ReportMode,
	
	[Parameter( Mandatory=$false)]
	[switch]$SendEmail,

	[Parameter( Mandatory=$false)]
	[switch]$AlertsOnly,	
	
	[Parameter( Mandatory=$false)]
	[switch]$Log

	)


#...................................
# Variables
#...................................

$now = Get-Date											#Used for timestamps
$date = $now.ToShortDateString()						#Short date format for email message subject
[array]$exchangeservers = @()							#Array for the Exchange server or servers to check
[int]$transportqueuewarn = 80                           #Change this to set transport queue warning threshold. Must be lower than high threshold.
[int]$transportqueuehigh = 100							#Change this to set transport queue high threshold. Must be higher than warning threshold.
[int]$cascurrentrequestswarn = 4000                     #Change this to set clients connections to CAS warning threshold. Must be lower than high threshold.
[int]$cascurrentrequestshigh = 200000                   #Change this to set clients connections to CAS high threshold. Must be higher than warning threshold.
$mapitimeout = 10										#Timeout for each MAPI connectivity test, in seconds
$pass = "Green"
$warn = "Yellow"
$fail = "Red"
$ip = $null
[array]$serversummary = @()								#Summary of issues found during server health checks
[array]$dagsummary = @()                                #Summary of issues found during DAG health checks
[array]$statisticssummary = @()                         #Summary of issues found during CAS connections statistics checks
[array]$report = @()
[bool]$alerts = $false
[array]$dags = @()										#Array for DAG health check
[array]$dagdatabases = @()								#Array for DAG databases
[int]$replqueuewarning = 8								#Threshold to consider a replication queue unhealthy
$dagreportbody = $null

$myDir = Split-Path -Parent $MyInvocation.MyCommand.Path

#...................................
# Modify these Variables (optional)
#...................................

$reportemailsubject = "Exchange Server Health Report"
$ignorelistfile = "$myDir\ignorelist.txt"
$logfile = "$myDir\exchangeserverhealth.log"

#...................................
# Modify these Email Settings
#...................................

$smtpsettings = @{
	To =  "administrator@exchangeserverpro.net"
	From = "exchangeserver@exchangeserverpro.net"
	Subject = "$reportemailsubject - $now"
	SmtpServer = "smtp.exchangeserverpro.net"
	}


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

#...................................
# Logfile Strings
#...................................

$logstring0 = "====================================="
$logstring1 = " Exchange Server Health Check"

#...................................
# Initialization Strings
#...................................

$initstring0 = "Initializing..."
$initstring1 = "Loading the Exchange Server PowerShell snapin"
$initstring2 = "The Exchange Server PowerShell snapin did not load."
$initstring3 = "Setting scope to entire forest"

#...................................
# Error/Warning Strings
#...................................

$string0 = "Server is not an Exchange server. "
$string1 = "Server is not reachable. "
$string3 = "------ Checking"
$string4 = "Could not test service health. "
$string5 = "required services not running. "
$string6 = "Could not check queue. "
$string7 = "Public Folder database not mounted. "
$string8 = "Skipping Edge Transport server. "
$string9 = "Mailbox databases not mounted. "
$string10 = "MAPI tests failed. "
$string11 = "Mail flow test failed. "
$string12 = "No Exchange Server 2003 checks performed. "
$string13 = "Server not found in DNS. "
$string14 = "Sending email. "
$string15 = "Done."
$string16 = "------ Finishing"
$string17 = "Unable to retrieve uptime. "
$string18 = "Ping failed. "
$string19 = "No alerts found, and AlertsOnly switch was used. No email sent. "
$string20 = "You have specified a single server to check"
$string21 = "Couldn't find the server $server. Script will terminate."
$string22 = "The file $ignorelistfile could not be found. No servers, DAGs or databases will be ignored."
$string23 = "You have specified a filename containing a list of servers to check"
$string24 = "The file $serverlist could not be found. Script will terminate."
$string25 = "Retrieving server list"
$string26 = "Removing servers in ignorelist from server list"
$string27 = "Beginning the server health checks"
$string28 = "Servers, DAGs and databases to ignore:"
$string29 = "Servers to check:"
$string30 = "Checking DNS"
$string31 = "DNS check passed"
$string32 = "Checking ping"
$string33 = "Ping test passed"
$string34 = "Checking uptime"
$string35 = "Checking service health"
$string36 = "Checking Hub Transport Server"
$string37 = "Checking Mailbox Server"
$string38 = "Ignore list contains no server names."
$string39 = "Checking public folder database"
$string40 = "Public folder database status is"
$string41 = "Checking mailbox databases"
$string42 = "Mailbox database status is"
$string43 = "Offline databases: "
$string44 = "Checking MAPI connectivity"
$string45 = "MAPI connectivity status is"
$string46 = "MAPI failed to: "
$string47 = "Checking mail flow"
$string48 = "Mail flow status is"
$string49 = "No active DBs"
$string50 = "Finished checking server"
$string51 = "Skipped"
$string52 = "Using alternative test for Exchange 2013 CAS-only server"
$string60 = "Beginning the DAG health checks"
$string61 = "Could not determine server with active database copy"
$string62 = "mounted on server that is activation preference"
$string63 = "unhealthy database copy count is"
$string64 = "healthy copy/replay queue count is"
$string65 = "(of"
$string66 = ")"
$string67 = "unhealthy content index count is"
$string68 = "DAGs to check:"
$string69 = "DAG databases to check"



#...................................
# Functions
#...................................

#This function is used to generate HTML for the DAG member health report
Function New-DAGMemberHTMLTableCell()
{
	param( $lineitem )
	
	$htmltablecell = $null

	switch ($($line."$lineitem"))
	{
		$null { $htmltablecell = "<td>n/a</td>" }
		"Passed" { $htmltablecell = "<td class=""pass"">$($line."$lineitem")</td>" }
		default { $htmltablecell = "<td class=""warn"">$($line."$lineitem")</td>" }
	}
	
	return $htmltablecell
}

#This function is used to generate HTML for the server health report
Function New-ServerHealthHTMLTableCell()
{
	param( $lineitem )
	
	$htmltablecell = $null
	
	switch ($($reportline."$lineitem"))
	{
		$success {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Success" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
        "Pass" {$htmltablecell = "<td class=""pass"">$($reportline."$lineitem")</td>"}
		"Warn" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
		"Access Denied" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
		"Fail" {$htmltablecell = "<td class=""fail"">$($reportline."$lineitem")</td>"}
        "Could not test service health. " {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
		"Unknown" {$htmltablecell = "<td class=""warn"">$($reportline."$lineitem")</td>"}
		default {$htmltablecell = "<td>$($reportline."$lineitem")</td>"}
	}
	
	return $htmltablecell
}

#This function is used to write the log file if -Log is used
Function Write-Logfile()
{
	param( $logentry )
	$timestamp = Get-Date -DisplayHint Time
	"$timestamp $logentry" | Out-File $logfile -Append
}

#This function is used to test service health for Exchange 2013 CAS-only servers
Function Test-E15CASServiceHealth()
{
	param ( $e15cas )
	
	$e15casservicehealth = $null
	$servicesrunning = @()
	$servicesnotrunning = @()
	$casservices = @(
		"IISAdmin",
		"W3Svc",
		"WinRM",
		"MSExchangeADTopology",
		"MSExchangeDiagnostics",
		"MSExchangeFrontEndTransport",
		#"MSExchangeHM",
		"MSExchangeIMAP4",
		"MSExchangePOP3",
		"MSExchangeServiceHost",
		"MSExchangeUMCR"
		)
		
	try {
		$servicestates = @(Get-WmiObject -ComputerName $e15cas -Class Win32_Service -ErrorAction STOP | where {$casservices -icontains $_.Name} | select name,state,startmode)
	}
	catch
	{
		if ($Log) {Write-LogFile $_.Exception.Message}
		Write-Warning $_.Exception.Message
		$e15casservicehealth = "Fail"
	}	
	
	if (!($e15casservicehealth))
	{
		$servicesrunning = @($servicestates | Where {$_.StartMode -eq "Auto" -and $_.State -eq "Running"})
		$servicesnotrunning = @($servicestates | Where {$_.Startmode -eq "Auto" -and $_.State -ne "Running"})
		if ($($servicesnotrunning.Count) -gt 0)
		{
			Write-Verbose "Service health check failed"
		    Write-Verbose "Services not running:"
		    foreach ($service in $servicesnotrunning)
		    {
		        Write-Verbose "- $($service.Name)"	
		    }
			$e15casservicehealth = "Fail"	
		}
		else
		{
			Write-Verbose "Service health check passed"
			$e15casservicehealth = "Pass"
		}
	}
	return $e15casservicehealth
}

#This function is used to test mail flow for Exchange 2013 Mailbox servers
Function Test-E15MailFlow()
{
	param ( $e15mailboxserver )

	$e15mailflowresult = $null
	
	Write-Verbose "Creating PSSession for $e15mailboxserver"
    $url = (Get-PowerShellVirtualDirectory -Server $e15mailboxserver -AdPropertiesOnly | Where {$_.Name -eq "Powershell (Default Web Site)"}).InternalURL.AbsoluteUri
    if ($url -eq $null)
    {
        $url = "http://$e15mailboxserver/powershell"
    }

	try
	{
	    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url -ErrorAction STOP
	}
	catch
	{
	    Write-Verbose "Something went wrong"
		if ($Log) {Write-LogFile $_.Exception.Message}
    	Write-Warning $_.Exception.Message
		$e15mailflowresult = "Fail"
	}

	try
	{
	    Write-Verbose "Running mail flow test on $e15mailboxserver"
	    $result = Invoke-Command -Session $session {Test-Mailflow} -ErrorAction STOP
	    $e15mailflowresult = $result.TestMailflowResult
	}
	catch
	{
	    Write-Verbose "An error occurred"
		if ($Log) {Write-LogFile $_.Exception.Message}
	    Write-Warning $_.Exception.Message
	    $e15mailflowresult = "Fail"
	}

	Write-Verbose "Mail flow test: $testresult"
	Write-Verbose "Removing PSSession"
	Remove-PSSession $session.Id

	return $e15mailflowresult
}

#This function is used to test replication health for Exchange 2010 DAG members in mixed 2010/2013 organizations
Function Test-E14ReplicationHealth()
{
	param ( $e14mailboxserver )

	$e14replicationhealth = $null
	
    #Find an E14 CAS in the same site
    $ADSite = (Get-ExchangeServer $e14mailboxserver).Site
    $e14cas = (Get-ExchangeServer | where {$_.IsClientAccessServer -and $_.AdminDisplayVersion -match "Version 14" -and $_.Site -eq $ADSite} | select -first 1).FQDN

	Write-Verbose "Creating PSSession for $e14cas"
    $url = (Get-PowerShellVirtualDirectory -Server $e14cas -AdPropertiesOnly | Where {$_.Name -eq "Powershell (Default Web Site)"}).InternalURL.AbsoluteUri
    if ($url -eq $null)
    {
        $url = "http://$e14cas/powershell"
    }

    Write-Verbose "Using URL $url"

	try
	{
	    $session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri $url -ErrorAction STOP
	}
	catch
	{
	    Write-Verbose "Something went wrong"
		if ($Log) {Write-LogFile $_.Exception.Message}
    	Write-Warning $_.Exception.Message
		#$e14replicationhealth = "Fail"
	}

	try
	{
	    Write-Verbose "Running replication health test on $e14mailboxserver"
	    #$e14replicationhealth = Invoke-Command -Session $session {Test-ReplicationHealth} -ErrorAction STOP
        $e14replicationhealth = Invoke-Command -Session $session -Args $e14mailboxserver.Name {Test-ReplicationHealth $args[0]} -ErrorAction STOP
	}
	catch
	{
	    Write-Verbose "An error occurred"
		if ($Log) {Write-LogFile $_.Exception.Message}
	    Write-Warning $_.Exception.Message
	    #$e14replicationhealth = "Fail"
	}

	#Write-Verbose "Replication health test: $e14replicationhealth"
	Write-Verbose "Removing PSSession"
	Remove-PSSession $session.Id

	return $e14replicationhealth
}


#...................................
# Initialize
#...................................

#Log file is overwritten each time the script is run to avoid
#very large log files from growing over time
if ($Log) {
	$timestamp = Get-Date -DisplayHint Time
	"$timestamp $logstring0" | Out-File $logfile
	Write-Logfile $logstring1
	Write-Logfile "  $now"
	Write-Logfile $logstring0
}

Write-Host $initstring0
if ($Log) {Write-Logfile $initstring0}

#Add Exchange 2010 snapin if not already loaded in the PowerShell session
if (!(Get-PSSnapin | where {$_.Name -eq "Microsoft.Exchange.Management.PowerShell.E2010"}))
{
	Write-Verbose $initstring1
	if ($Log) {Write-Logfile $initstring1}
	try
	{
		Add-PSSnapin Microsoft.Exchange.Management.PowerShell.E2010 -ErrorAction STOP
	}
	catch
	{
		#Snapin was not loaded
		Write-Verbose $initstring2
		if ($Log) {Write-Logfile $initstring2}
		Write-Warning $_.Exception.Message
		EXIT
	}
	. $env:ExchangeInstallPath\bin\RemoteExchange.ps1
	Connect-ExchangeServer -auto -AllowClobber
}


#Set scope to include entire forest
Write-Verbose $initstring3
if ($Log) {Write-Logfile $initstring3}
if (!(Get-ADServerSettings).ViewEntireForest)
{
	Set-ADServerSettings -ViewEntireForest $true -WarningAction SilentlyContinue
}


#...................................
# Script
#...................................

#Check if a single server was specified
if ($server)
{
	#Run for single specified server
	[bool]$NoDAG = $true
	Write-Verbose $string20
	if ($Log) {Write-Logfile $string20}
	try
	{
		$exchangeservers = Get-ExchangeServer $server -ErrorAction STOP
	}
	catch
	{
		#Exit because single server name was specified and couldn't be found in the organization
		Write-Verbose $string21
		if ($Log) {Write-Logfile $string21}
		Write-Error $_.Exception.Message
		EXIT
	}
}
elseif ($serverlist)
{
	#Run for a list of servers in a text file
	[bool]$NoDAG = $true
	Write-Verbose $string23
	if ($Log) {Write-Logfile $string23}
	try
	{
        $tmpservers = @(Get-Content $serverlist -ErrorAction STOP)
		$exchangeservers = @($tmpservers | Get-ExchangeServer)
    }
    catch
	{
		#Exit because file could not be found
        Write-Verbose $string24
		if ($Log) {Write-Logfile $string24}
		Write-Error $_.Exception.Message
		EXIT
    }
}
else
{
	#This is the list of servers, DAGs, and databases to never alert for
	try
	{
        $ignorelist = @(Get-Content $ignorelistfile -ErrorAction STOP)
		if ($Log) {Write-Logfile $string28}
		if ($Log) {
			if ($($ignorelist.count) -gt 0)
			{
				foreach ($line in $ignorelist)
				{
					Write-Logfile "- $line"
				}
			}
			else
			{
				Write-Logfile $string38
			}
		}
    }
    catch
	{
		Write-Warning $string22
		if ($Log) {Write-Logfile $string22}
    }
    
	#Get all servers
	Write-Verbose $string25
	if ($Log) {Write-Logfile $string25}
	$tmpservers = @(Get-ExchangeServer | sort site,name)
	
	#Remove the servers that are ignored from the list of servers to check
	Write-Verbose $string26
	if ($Log) {Write-Logfile $string26}
	foreach ($tmpserver in $tmpservers)
	{
		if (!($ignorelist -icontains $tmpserver.name))
		{
			$exchangeservers = $exchangeservers += $tmpserver.identity
		}
	}

	if ($Log) {Write-Logfile $string29}
	if ($Log) {
		foreach ($server in $exchangeservers)
		{
			Write-Logfile "- $server"
		}
	}
}

### Check if any Exchange 2013 servers exist
if (Get-ExchangeServer | Where {$_.AdminDisplayVersion -like "Version 15.*"})
{
	[bool]$HasE15 = $true
}

### Begin the Exchange Server health checks
Write-Verbose $string27
if ($Log) {Write-Logfile $string27}
foreach ($server in $exchangeservers)
{
	Write-Host -ForegroundColor White "$string3 $server"
	if ($Log) {Write-Logfile "$string3 $server"}
	
	#Find out some details about the server
	try
	{
		$serverinfo = Get-ExchangeServer $server -ErrorAction Stop
	}
	catch
	{
		Write-Warning $_.Exception.Message
		if ($Log) {Write-Logfile $_.Exception.Message}
		$serverinfo = $null
	}

	if ($serverinfo -eq $null )
	{
		#Server is not an Exchange server
		Write-Host -ForegroundColor $warn $string0
		if ($Log) {Write-Logfile $string0}
	}
	elseif ( $serverinfo.IsEdgeServer )
	{
		Write-Host -ForegroundColor White $string8
		if ($Log) {Write-Logfile $string8}
	}
	else
	{
		#Server is an Exchange server, continue the health check

		#Custom object properties
		$serverObj = New-Object PSObject
		$serverObj | Add-Member NoteProperty -Name "Server" -Value $server
		
        #Skip Site attribute for Exchange 2003 servers
        if ($serverinfo.AdminDisplayVersion -like "Version 6.*")
		{
			$serverObj | Add-Member NoteProperty -Name "Site" -Value "n/a"
		}
        else
        {
		    $site = ($serverinfo.site.ToString()).Split("/")
		    $serverObj | Add-Member NoteProperty -Name "Site" -Value $site[-1]
        }
		
        #Null and n/a the rest, will be populated as script progresses
		$serverObj | Add-Member NoteProperty -Name "DNS" -Value $null
		$serverObj | Add-Member NoteProperty -Name "Ping" -Value $null
		$serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $null
		$serverObj | Add-Member NoteProperty -Name "Version" -Value $null
		$serverObj | Add-Member NoteProperty -Name "Roles" -Value $null
		$serverObj | Add-Member NoteProperty -Name "Client Access Server Role Services" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Hub Transport Server Role Services" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Mailbox Server Role Services" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Unified Messaging Server Role Services" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Queue Length" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "PF DBs Mounted" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "MB DBs Mounted" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "n/a"
		$serverObj | Add-Member NoteProperty -Name "MAPI Test" -Value "n/a"

		#Check server name resolves in DNS
		if ($Log) {Write-Logfile $string30}
		Write-Host "DNS Check: " -NoNewline;
		try 
		{
			$ip = @([System.Net.Dns]::GetHostByName($server).AddressList | Select-Object IPAddressToString -ExpandProperty IPAddressToString)
		}
		catch
		{
			Write-Host -ForegroundColor $warn $_.Exception.Message
			if ($Log) {Write-Logfile $_.Exception.Message}
			$ip = $null
		}

		if ( $ip -ne $null )
		{
			Write-Host -ForegroundColor $pass "Pass"
			if ($Log) {Write-Logfile $string31}
			$serverObj | Add-Member NoteProperty -Name "DNS" -Value "Pass" -Force

			#Is server online
			if ($Log) {Write-Logfile $string32}
			Write-Host "Ping Check: " -NoNewline; 
			
			$ping = $null
			try
			{
				$ping = Test-Connection $server -Quiet -ErrorAction Stop
			}
			catch
			{
				Write-Host -ForegroundColor $warn $_.Exception.Message
				if ($Log) {Write-Logfile $_.Exception.Message}
			}

			switch ($ping)
			{
				$true {
					Write-Host -ForegroundColor $pass "Pass"
					$serverObj | Add-Member NoteProperty -Name "Ping" -Value "Pass" -Force
					if ($Log) {Write-Logfile $string33}
					}
				default {
					Write-Host -ForegroundColor $fail "Fail"
					$serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
					$serversummary += "$server - $string18"
					if ($Log) {Write-Logfile $string18}
					}
			}
			
			#Uptime check, even if ping fails
			if ($Log) {Write-Logfile $string34}
			[int]$uptime = $null
			#$laststart = $null
            $OS = $null
		
			try 
			{
				#$laststart = [System.Management.ManagementDateTimeconverter]::ToDateTime((Get-WmiObject -Class Win32_OperatingSystem -computername $server -ErrorAction Stop).LastBootUpTime)
                $OS = Get-WmiObject -Class Win32_OperatingSystem -ComputerName $server -ErrorAction STOP
			}
			catch
			{
				Write-Host -ForegroundColor $warn $_.Exception.Message
				if ($Log) {Write-Logfile $_.Exception.Message}
			}
			
            Write-Host "Uptime (hrs): " -NoNewline

			if ($OS -eq $null)
			{
				[string]$uptime = $string17
				if ($Log) {Write-Logfile $string17}
				switch ($ping)
				{
                	$true {	$serversummary += "$server - $string17" }
					default { $serversummary += "$server - $string17" }
				}
			}
			else
			{
				$timespan = $OS.ConvertToDateTime($OS.LocalDateTime) – $OS.ConvertToDateTime($OS.LastBootUpTime)
				[int]$uptime = "{0:00}" -f $timespan.TotalHours
				Switch ($uptime -gt 23) {
				    $true { Write-Host -ForegroundColor $pass $uptime }
				    $false { Write-Host -ForegroundColor $warn $uptime; $serversummary += "$server - Uptime is less than 24 hours" }
				    default { Write-Host -ForegroundColor $warn $uptime; $serversummary += "$server - Uptime is less than 24 hours" }
			    }
			}

			if ($Log) {Write-Logfile "Uptime is $uptime hours"}

			$serverObj | Add-Member NoteProperty -Name "Uptime (hrs)" -Value $uptime -Force	
			
			if ($ping -or ($uptime -ne $string17))
			{
				#Determine the friendly version number
				$ExVer = $serverinfo.AdminDisplayVersion
				Write-Host "Server version: " -NoNewline;
				
				if ($ExVer -like "Version 6.*")
				{
					$version = "Exchange 2003"
				}
				
				if ($ExVer -like "Version 8.*")
				{
					$version = "Exchange 2007"
				}
				
				if ($ExVer -like "Version 14.*")
				{
					$version = "Exchange 2010"
				}
				
				if ($ExVer -like "Version 15.0*")
				{
					$version = "Exchange 2013"
				}

				if ($ExVer -like "Version 15.1*")
				{
					$version = "Exchange 2016"
				}
				
				Write-Host $version
				if ($Log) {Write-Logfile "Server is running $version"}
				$serverObj | Add-Member NoteProperty -Name "Version" -Value $version -Force
			
				if ($version -eq "Exchange 2003")
				{
					Write-Host $string12
					if ($Log) {Write-Logfile $string12}
				}

				#START - Exchange 2013/2010/2007 Health Checks
				if ($version -ne "Exchange 2003")
				{
					Write-Host "Roles:" $serverinfo.ServerRole
					if ($Log) {Write-Logfile "Server roles: $($serverinfo.ServerRole)"}
					$serverObj | Add-Member NoteProperty -Name "Roles" -Value $serverinfo.ServerRole -Force
					
					$IsEdge = $serverinfo.IsEdgeServer		
					$IsHub = $serverinfo.IsHubTransportServer
					$IsCAS = $serverinfo.IsClientAccessServer
					$IsMB = $serverinfo.IsMailboxServer

					#START - General Server Health Check
					#Skipping Edge Transports for the general health check, as firewalls usually get
					#in the way. If you want to include them, remove this If.
					if ($IsEdge -ne $true)
					{
						#Service health is an array due to how multi-role servers return Test-ServiceHealth status
						if ($Log) {Write-Logfile $string35}
                        $servicehealth = @()
						$e15casservicehealth = @()
						try {
							$servicehealth = @(Test-ServiceHealth $server -ErrorAction Stop)
						}
						catch {
							#Workaround for Test-ServiceHealth problem with CAS-only Exchange 2013 servers
							#More info: http://exchangeserverpro.com/exchange-2013-test-servicehealth-error/
							if ($_.Exception.Message -like "*There are no Microsoft Exchange 2007 server roles installed*")
							{
								if ($Log) {Write-Logfile $string52}
								$e15casservicehealth = Test-E15CASServiceHealth($server)
							}
							else
							{
								$serversummary += "$server - $string4"
								Write-Host -ForegroundColor $warn $string4 ":" $_.Exception
								if ($Log) {Write-Logfile $_.Exception}
	                            $serverObj | Add-Member NoteProperty -Name "Client Access Server Role Services" -Value $string4 -Force
			                    $serverObj | Add-Member NoteProperty -Name "Hub Transport Server Role Services" -Value $string4 -Force
			                    $serverObj | Add-Member NoteProperty -Name "Mailbox Server Role Services" -Value $string4 -Force
			                    $serverObj | Add-Member NoteProperty -Name "Unified Messaging Server Role Services" -Value $string4 -Force
							}
						}
							
						if ($servicehealth)
						{
							foreach($s in $servicehealth)
							{
								$roleName = $s.Role
								Write-Host $roleName "Services: " -NoNewline;
															
								switch ($s.RequiredServicesRunning)
								{
									$true {
										$svchealth = "Pass"
										Write-Host -ForegroundColor $pass "Pass"
										}
									$false {
										$svchealth = "Fail"
										Write-Host -ForegroundColor $fail "Fail"
										$serversummary += "$server - $rolename $string5"
										}
                                    default {
										$svchealth = "Warn"
										Write-Host -ForegroundColor $warn "Warning"
										$serversummary += "$server - $rolename $string5"
										}
								}

								switch ($s.Role)
								{
									$casrole { $serverinfoservices = "Client Access Server Role Services" }
									$htrole { $serverinfoservices = "Hub Transport Server Role Services" }
									$mbrole { $serverinfoservices = "Mailbox Server Role Services" }
									$umrole { $serverinfoservices = "Unified Messaging Server Role Services" }
								}
								if ($Log) {Write-Logfile "$serverinfoservices status is $svchealth"}	
								$serverObj | Add-Member NoteProperty -Name $serverinfoservices -Value $svchealth -Force
							}
						}
						
						if ($e15casservicehealth)
						{
							$serverinfoservices = "Client Access Server Role Services"
							if ($Log) {Write-Logfile "$serverinfoservices status is $e15casservicehealth"}
							$serverObj | Add-Member NoteProperty -Name $serverinfoservices -Value $e15casservicehealth -Force
							Write-Host $serverinfoservices ": " -NoNewline;
							switch ($e15casservicehealth)
							{
								"Pass" { Write-Host -ForegroundColor $pass "Pass" }
								"Fail" { Write-Host -ForegroundColor $fail "Fail" }
							}
						}
					}
					#END - General Server Health Check

					#START - Hub Transport Server Check
					if ($IsHub)
					{
						$q = $null
						if ($Log) {Write-Logfile $string36}
						Write-Host "Total Queue: " -NoNewline; 
						try {
							$q = Get-Queue -server $server -ErrorAction Stop
						}
						catch {
							$serversummary += "$server - $string6"
							Write-Host -ForegroundColor $warn $string6
							Write-Warning $_.Exception.Message
							if ($Log) {Write-Logfile $string6}
							if ($Log) {Write-Logfile $_.Exception.Message}
						}
						
						if ($q)
						{
							$qcount = $q | Measure-Object MessageCount -Sum
							[int]$qlength = $qcount.sum
							$serverObj | Add-Member NoteProperty -Name "Queue Length" -Value $qlength -Force
							if ($Log) {Write-Logfile "Queue length is $qlength"}
							if ($qlength -le $transportqueuewarn)
							{
								Write-Host -ForegroundColor $pass $qlength
								$serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Pass ($qlength)" -Force
							}
							elseif ($qlength -gt $transportqueuewarn -and $qlength -lt $transportqueuehigh)
							{
								Write-Host -ForegroundColor $warn $qlength
                                $serversummary += "$server - Transport queue is above warning threshold" 
								$serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Warn ($qlength)" -Force
							}
							else
							{
								Write-Host -ForegroundColor $fail $qlength
                                $serversummary += "$server - Transport queue is above high threshold"
								$serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Fail ($qlength)" -Force
							}
						}
						else
						{
							$serverObj | Add-Member NoteProperty -Name "Transport Queue" -Value "Unknown" -Force
						}
					}
					#END - Hub Transport Server Check

					#START - Mailbox Server Check
					if ($IsMB)
					{
						if ($Log) {Write-Logfile $string37}
						
						#Get the PF and MB databases
						[array]$pfdbs = @(Get-PublicFolderDatabase -server $server -status -WarningAction SilentlyContinue)
						[array]$mbdbs = @(Get-MailboxDatabase -server $server -status | Where {$_.Recovery -ne $true})
                        
                        if ($version -ne "Exchange 2007")
                        {
						    [array]$activedbs = @(Get-MailboxDatabase -server $server -status | Where {$_.Recovery -ne $true -and $_.MountedOnServer -eq ($serverinfo.fqdn)})
                        }
                        else
                        {
                            [array]$activedbs = $mbdbs
                        }
						
						#START - Database Mount Check
						
						#Check public folder databases
						if ($pfdbs.count -gt 0)
						{
							if ($Log) {Write-Logfile $string39}
							Write-Host "Public Folder databases mounted: " -NoNewline;
							[string]$pfdbstatus = "Pass"
							[array]$alertdbs = @()
							foreach ($db in $pfdbs)
							{
								if (($db.mounted) -ne $true)
								{
									$pfdbstatus = "Fail"
									$alertdbs += $db.name
								}
							}

							$serverObj | Add-Member NoteProperty -Name "PF DBs Mounted" -Value $pfdbstatus -Force
							if ($Log) {Write-Logfile "$string40 $pfdbstatus"}
							
							if ($alertdbs.count -eq 0)
							{
								Write-Host -ForegroundColor $pass $pfdbstatus
							}
							else
							{
								Write-Host -ForegroundColor $fail $pfdbstatus
								$serversummary += "$server - $string7"
								Write-Host "Offline databases:"
								foreach ($al in $alertdbs)
								{
									Write-Host -ForegroundColor $fail `t$al
								}
							}
						}
						
						#Check mailbox databases
						if ($mbdbs.count -gt 0)
						{
							if ($Log) {Write-Logfile $string41}
						
							[string]$mbdbstatus = "Pass"
							[array]$alertdbs = @()

							Write-Host "Mailbox databases mounted: " -NoNewline;
							foreach ($db in $mbdbs)
							{
								if (($db.mounted) -ne $true)
								{
									$mbdbstatus = "Fail"
									$alertdbs += $db.name
								}
							}

							$serverObj | Add-Member NoteProperty -Name "MB DBs Mounted" -Value $mbdbstatus -Force
							if ($Log) {Write-Logfile "$string42 $mbdbstatus"}
							
							if ($alertdbs.count -eq 0)
							{
								Write-Host -ForegroundColor $pass $mbdbstatus
							}
							else
							{
								$serversummary += "$server - $string9"
								Write-Host -ForegroundColor $fail $mbdbstatus
								Write-Host $string43
								if ($Log) {Write-Logfile $string43}
								foreach ($al in $alertdbs)
								{
									Write-Host -ForegroundColor $fail `t$al
									if ($Log) {Write-Logfile "- $al"}
								}
							}
						}
						
						#END - Database Mount Check
						
						#START - MAPI Connectivity Test
						if ($activedbs.count -gt 0 -or $pfdbs.count -gt 0 -or $version -eq "Exchange 2007")
						{
							[string]$mapiresult = "Unknown"
							[array]$alertdbs = @()
							if ($Log) {Write-Logfile $string44}
							Write-Host "MAPI connectivity: " -NoNewline;
							foreach ($db in $mbdbs)
							{
								$mapistatus = Test-MapiConnectivity -Database $db.Identity -PerConnectionTimeout $mapitimeout
                                if ($mapistatus.Result.Value -eq $null)
                                {
                                    $mapiresult = $mapistatus.Result
                                }
                                else
                                {
                                    $mapiresult = $mapistatus.Result.Value
                                }
                                if (($mapiresult) -ne "Success")
								{
									$mapistatus = "Fail"
									$alertdbs += $db.name
								}
							}

							$serverObj | Add-Member NoteProperty -Name "MAPI Test" -Value  $mapiresult -Force
							if ($Log) {Write-Logfile "$string45  $mapiresult"}
							
							if ($alertdbs.count -eq 0)
							{
								Write-Host -ForegroundColor $pass  $mapiresult
							}
							else
							{
								$serversummary += "$server - $string10"
								Write-Host -ForegroundColor $fail  $mapiresult
								Write-Host $string46
								if ($Log) {Write-Logfile $string46}
								foreach ($al in $alertdbs)
								{
									Write-Host -ForegroundColor $fail `t$al
									if ($Log) {Write-Logfile "- $al"}
								}
							}
						}
						#END - MAPI Connectivity Test
						
						#START - Mail Flow Test
						if ($version -eq "Exchange 2007" -and $mbdbs.count -gt 0 -and $HasE15)
						{
							#Skip Exchange 2007 mail flow tests when run from Exchange 2013
							if ($Log) {Write-Logfile $string47}
							Write-Host "Mail flow test: Skipped"
							$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value $string51 -Force
							if ($Log) {Write-Logfile $string51}
						}
						elseif ($activedbs.count -gt 0 -and $HasE15)
						{
							if ($Log) {Write-Logfile $string47}
							Write-Host "Mail flow test: " -NoNewline;
							$e15mailflowresult = Test-E15MailFlow($Server)
							$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value $e15mailflowresult -Force
							if ($Log) {Write-Logfile "$string48 $e15mailflowresult"}
							
							if ($e15mailflowresult -eq $success)
							{
								Write-Host -ForegroundColor $pass $e15mailflowresult
								$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Pass" -Force
							}
							else
							{
								$serversummary += "$server - $string11"
								Write-Host -ForegroundColor $fail $e15mailflowresult
								$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Fail" -Force
							}
						}
						elseif ($activedbs.count -gt 0 -or ($version -eq "Exchange 2007" -and $mbdbs.count -gt 0))
						{
							$flow = $null
							$testmailflowresult = $null
							
							if ($Log) {Write-Logfile $string47}
							Write-Host "Mail flow test: " -NoNewline;
							try
							{
								$flow = Test-Mailflow $server -ErrorAction Stop
							}
							catch
							{
								$testmailflowresult = $_.Exception.Message
								if ($Log) {Write-Logfile $_.Exception.Message}
							}
							
							if ($flow)
							{
								$testmailflowresult = $flow.testmailflowresult
								if ($Log) {Write-Logfile "$string48 $testmailflowresult"}
							}

							if ($testmailflowresult -eq "Success" -or $testmailflowresult -eq $success)
							{
								Write-Host -ForegroundColor $pass $testmailflowresult
								$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Pass" -Force
							}
							else
							{
								$serversummary += "$server - $string11"
								Write-Host -ForegroundColor $fail $testmailflowresult
								$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value "Fail" -Force
							}
						}
						else
						{
							Write-Host "Mail flow test: No active mailbox databases"
							$serverObj | Add-Member NoteProperty -Name "Mail Flow Test" -Value $string49 -Force
							if ($Log) {Write-Logfile $string49}
						}
						#END - Mail Flow Test
					}
					#END - Mailbox Server Check

				}
				#END - Exchange 2013/2010/2007 Health Checks
				if ($Log) {Write-Logfile "$string50 $server"}
				$report = $report + $serverObj
			}
			else
			{
				#Server is not reachable and uptime could not be retrieved
				Write-Host -ForegroundColor $warn $string1
				if ($Log) {Write-Logfile $string1}
				$serversummary += "$server - $string1"
				$serverObj | Add-Member NoteProperty -Name "Ping" -Value "Fail" -Force
				if ($Log) {Write-Logfile "$string50 $server"}
				$report = $report + $serverObj
			}
		}
		else
		{
			Write-Host -ForegroundColor $Fail "Fail"
			Write-Host -ForegroundColor $warn $string13
			if ($Log) {Write-Logfile $string13}
			$serversummary += "$server - $string13"
			$serverObj | Add-Member NoteProperty -Name "DNS" -Value "Fail" -Force
			if ($Log) {Write-Logfile "$string50 $server"}
			$report = $report + $serverObj
		}
	}	
}
### End the Exchange Server health checks


### Begin DAG Health Report

#Check if -Server or -Serverlist parameter was used, and skip if it was
if (!($NoDAG))
{
	if ($Log) {Write-Logfile $string60}
	Write-Verbose "Retrieving Database Availability Groups"

	#Get all DAGs
	$tmpdags = @(Get-DatabaseAvailabilityGroup)
	$tmpstring = "$($tmpdags.count) DAGs found"
	Write-Verbose $tmpstring
	if ($Log) {Write-Logfile $tmpstring}

	#Remove DAGs in ignorelist
	foreach ($tmpdag in $tmpdags)
	{
		if (!($ignorelist -icontains $tmpdag.name))
		{
			$dags += $tmpdag
		}
	}

	$tmpstring = "$($dags.count) DAGs will be checked"
	Write-Verbose $tmpstring
	if ($Log) {Write-Logfile $tmpstring}

	if ($Log) {Write-Logfile $string68}
	if ($Log) {
		foreach ($dag in $dags)
		{
			Write-Logfile "- $dag"
		}
	}
}

if ($($dags.count) -gt 0)
{
	foreach ($dag in $dags)
	{
		
		#Strings for use in the HTML report/email
		$dagsummaryintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Summary:</p>"
		$dagdetailintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Health Details:</p>"
		$dagmemberintro = "<p>Database Availability Group <strong>$($dag.Name)</strong> Member Health:</p>"

		$dagdbcopyReport = @()		#Database copy health report
		$dagciReport = @()			#Content Index health report
		$dagmemberReport = @()		#DAG member server health report
		$dagdatabaseSummary = @()	#Database health summary report
		$dagdatabases = @()			#Array of databases in the DAG
		
		$tmpstring = "---- Processing DAG $($dag.Name)"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}
		
		$dagmembers = @($dag | Select-Object -ExpandProperty Servers | Sort-Object Name)
		$tmpstring = "$($dagmembers.count) DAG members found"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}
		
		#Get all databases in the DAG
        if ($HasE15)
        {
		    $tmpdatabases = @(Get-MailboxDatabase -Status -IncludePreExchange2013 | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $dag.Name} | Sort-Object Name)
        }
        else
        {
		    $tmpdatabases = @(Get-MailboxDatabase -Status | Where-Object {$_.MasterServerOrAvailabilityGroup -eq $dag.Name} | Sort-Object Name)
        }

		foreach ($tmpdatabase in $tmpdatabases)
		{
			if (!($ignorelist -icontains $tmpdatabase.name))
			{
				$dagdatabases += $tmpdatabase
			}
		}
				
		$tmpstring = "$($dagdatabases.count) DAG databases will be checked"
		Write-Verbose $tmpstring
		if ($Log) {Write-Logfile $tmpstring}

		if ($Log) {Write-Logfile $string69}
		if ($Log) {
			foreach ($database in $dagdatabases)
			{
				Write-Logfile "- $database"
			}
		}
		
		foreach ($database in $dagdatabases)
		{
			$tmpstring = "---- Processing database $database"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}

			#Custom object for Database
			$objectHash = @{
				"Database" = $database.Identity
				"Mounted on" = "Unknown"
				"Preference" = $null
				"Total Copies" = $null
				"Healthy Copies" = $null
				"Unhealthy Copies" = $null
				"Healthy Queues" = $null
				"Unhealthy Queues" = $null
				"Lagged Queues" = $null
				"Healthy Indexes" = $null
				"Unhealthy Indexes" = $null
				}
			$databaseObj = New-Object PSObject -Property $objectHash

			$dbcopystatus = @($database | Get-MailboxDatabaseCopyStatus)
			$tmpstring = "$database has $($dbcopystatus.Count) copies"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}
			
			foreach ($dbcopy in $dbcopystatus)
			{
				#Custom object for DB copy
				$objectHash = @{
					"Database Copy" = $dbcopy.Identity
					"Database Name" = $dbcopy.DatabaseName
					"Mailbox Server" = $null
					"Activation Preference" = $null
					"Status" = $null
					"Copy Queue" = $null
					"Replay Queue" = $null
					"Replay Lagged" = $null
					"Truncation Lagged" = $null
					"Content Index" = $null
					}
				$dbcopyObj = New-Object PSObject -Property $objectHash
				
				$tmpstring = "Database Copy: $($dbcopy.Identity)"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				$mailboxserver = $dbcopy.MailboxServer
				$tmpstring = "Server: $mailboxserver"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}

				$pref = ($database | Select-Object -ExpandProperty ActivationPreference | Where-Object {$_.Key -eq $mailboxserver}).Value
				$tmpstring = "Activation Preference: $pref"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}

				$copystatus = $dbcopy.Status
				$tmpstring = "Status: $copystatus"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				[int]$copyqueuelength = $dbcopy.CopyQueueLength
				$tmpstring = "Copy Queue: $copyqueuelength"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				[int]$replayqueuelength = $dbcopy.ReplayQueueLength
				$tmpstring = "Replay Queue: $replayqueuelength"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				if ($($dbcopy.ContentIndexErrorMessage -match "is disabled in Active Directory"))
                {
                    $contentindexstate = "Disabled"
                }
                else
                {
                    $contentindexstate = $dbcopy.ContentIndexState
                }
				$tmpstring = "Content Index: $contentindexstate"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}				

				#Checking whether this is a replay lagged copy
				$replaylagcopies = @($database | Select -ExpandProperty ReplayLagTimes | Where-Object {$_.Value -gt 0})
				if ($($replaylagcopies.count) -gt 0)
	            {
	                [bool]$replaylag = $false
	                foreach ($replaylagcopy in $replaylagcopies)
				    {
					    if ($replaylagcopy.Key -eq $mailboxserver)
					    {
						    $tmpstring = "$database is replay lagged on $mailboxserver"
							Write-Verbose $tmpstring
							if ($Log) {Write-Logfile $tmpstring}
						    [bool]$replaylag = $true
					    }
				    }
	            }
	            else
				{
				   [bool]$replaylag = $false
				}
	            $tmpstring = "Replay lag is $replaylag"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}				
						
				#Checking for truncation lagged copies
				$truncationlagcopies = @($database | Select -ExpandProperty TruncationLagTimes | Where-Object {$_.Value -gt 0})
				if ($($truncationlagcopies.count) -gt 0)
	            {
	                [bool]$truncatelag = $false
	                foreach ($truncationlagcopy in $truncationlagcopies)
				    {
					    if ($truncationlagcopy.Key -eq $mailboxserver)
					    {
						    $tmpstring = "$database is truncate lagged on $mailboxserver"
							Write-Verbose $tmpstring
							if ($Log) {Write-Logfile $tmpstring}							
							[bool]$truncatelag = $true
					    }
				    }
	            }
	            else
				{
				   [bool]$truncatelag = $false
				}
	            $tmpstring = "Truncation lag is $truncatelag"
				Write-Verbose $tmpstring
				if ($Log) {Write-Logfile $tmpstring}
				
				$dbcopyObj | Add-Member NoteProperty -Name "Mailbox Server" -Value $mailboxserver -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Activation Preference" -Value $pref -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Status" -Value $copystatus -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Copy Queue" -Value $copyqueuelength -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Replay Queue" -Value $replayqueuelength -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Replay Lagged" -Value $replaylag -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Truncation Lagged" -Value $truncatelag -Force
				$dbcopyObj | Add-Member NoteProperty -Name "Content Index" -Value $contentindexstate -Force
				
				$dagdbcopyReport += $dbcopyObj
			}
		
			$copies = @($dagdbcopyReport | Where-Object { ($_."Database Name" -eq $database) })
		
			$mountedOn = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Mailbox Server"
			if ($mountedOn)
			{
				$databaseObj | Add-Member NoteProperty -Name "Mounted on" -Value $mountedOn -Force
			}
		
			$activationPref = ($copies | Where-Object { ($_.Status -eq "Mounted") })."Activation Preference"
			$databaseObj | Add-Member NoteProperty -Name "Preference" -Value $activationPref -Force

			$totalcopies = $copies.count
			$databaseObj | Add-Member NoteProperty -Name "Total Copies" -Value $totalcopies -Force
		
			$healthycopies = @($copies | Where-Object { (($_.Status -eq "Mounted") -or ($_.Status -eq "Healthy")) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Healthy Copies" -Value $healthycopies -Force
			
			$unhealthycopies = @($copies | Where-Object { (($_.Status -ne "Mounted") -and ($_.Status -ne "Healthy")) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Copies" -Value $unhealthycopies -Force

			$healthyqueues  = @($copies | Where-Object { (($_."Copy Queue" -lt $replqueuewarning) -and (($_."Replay Queue" -lt $replqueuewarning)) -and ($_."Replay Lagged" -eq $false)) }).Count
	        $databaseObj | Add-Member NoteProperty -Name "Healthy Queues" -Value $healthyqueues -Force

			$unhealthyqueues = @($copies | Where-Object { (($_."Copy Queue" -ge $replqueuewarning) -or (($_."Replay Queue" -ge $replqueuewarning) -and ($_."Replay Lagged" -eq $false))) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Queues" -Value $unhealthyqueues -Force

			$laggedqueues = @($copies | Where-Object { ($_."Replay Lagged" -eq $true) -or ($_."Truncation Lagged" -eq $true) }).Count
			$databaseObj | Add-Member NoteProperty -Name "Lagged Queues" -Value $laggedqueues -Force

			$healthyindexes = @($copies | Where-Object { ($_."Content Index" -eq "Healthy" -or $_."Content Index" -eq "Disabled") }).Count
			$databaseObj | Add-Member NoteProperty -Name "Healthy Indexes" -Value $healthyindexes -Force
			
			$unhealthyindexes = @($copies | Where-Object { ($_."Content Index" -ne "Healthy" -and $_."Content Index" -ne "Disabled") }).Count
			$databaseObj | Add-Member NoteProperty -Name "Unhealthy Indexes" -Value $unhealthyindexes -Force
			
			$dagdatabaseSummary += $databaseObj
		
		}
		
		#Get Test-Replication Health results for each DAG member
		foreach ($dagmember in $dagmembers)
		{
            $replicationhealth = $null

            $replicationhealthitems = @{ClusterService = $null
                                        ReplayService = $null
                                        ActiveManager = $null
                                        TasksRpcListener = $null
                                        TcpListener = $null
                                        ServerLocatorService = $null
                                        DagMembersUp = $null
                                        ClusterNetwork = $null
                                        QuorumGroup = $null
                                        FileShareQuorum = $null
                                        DatabaseRedundancy = $null
                                        DatabaseAvailability = $null
                                        DBCopySuspended = $null
                                        DBCopyFailed = $null
                                        DBInitializing = $null
                                        DBDisconnected = $null
                                        DBLogCopyKeepingUp = $null
                                        DBLogReplayKeepingUp = $null
                                        }

			$memberObj = New-Object PSObject -Property $replicationhealthitems
			$memberObj | Add-Member NoteProperty -Name "Server" -Value $($dagmember.Name)
		
			$tmpstring = "---- Checking replication health for $($dagmember.Name)"
			Write-Verbose $tmpstring
			if ($Log) {Write-Logfile $tmpstring}
			
			try
            {
                $replicationhealth = $dagmember | Invoke-Command {Test-ReplicationHealth -ErrorAction STOP} 
            }
            catch
            {
		        if ($Log) {Write-Logfile "Using E14 replication health test workaround"}
                $replicationhealth = Test-E14ReplicationHealth $dagmember
            }
			
	        foreach ($healthitem in $replicationhealth)
	        {
                if ($($healthitem.Result) -eq $null)
                {
                    $healthitemresult = "n/a"
                }
                else
                {
                    $healthitemresult = $($healthitem.Result)
                }
                $tmpstring = "$($healthitem.Check) $healthitemresult"
		        Write-Verbose $tmpstring
		        if ($Log) {Write-Logfile $tmpstring}
		        $memberObj | Add-Member NoteProperty -Name $($healthitem.Check) -Value $healthitemresult -Force
	        }
			$dagmemberReport += $memberObj
		}

		
		#Generate the HTML from the DAG health checks
		if ($SendEmail -or $ReportFile)
		{
		
			####Begin Summary Table HTML
			$dagdatabaseSummaryHtml = $null
			#Begin Summary table HTML header
			$htmltableheader = "<p>
							<table>
							<tr>
							<th>Database</th>
							<th>Mounted on</th>
							<th>Preference</th>
							<th>Total Copies</th>
							<th>Healthy Copies</th>
							<th>Unhealthy Copies</th>
							<th>Healthy Queues</th>
							<th>Unhealthy Queues</th>
							<th>Lagged Queues</th>
							<th>Healthy Indexes</th>
							<th>Unhealthy Indexes</th>
							</tr>"

			$dagdatabaseSummaryHtml += $htmltableheader
			#End Summary table HTML header
			
			#Begin Summary table HTML rows
			foreach ($line in $dagdatabaseSummary)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line.Database)</strong></td>"
				
				#Warn if mounted server is still unknown
				switch ($($line."Mounted on"))
				{
					"Unknown" {
						$htmltablerow += "<td class=""warn"">$($line."Mounted on")</td>"
						$dagsummary += "$($line.Database) - $string61"
						}
					default { $htmltablerow += "<td>$($line."Mounted on")</td>" }
				}
				
				#Warn if DB is mounted on a server that is not Activation Preference 1
				if ($($line.Preference) -gt 1)
				{
					$htmltablerow += "<td class=""warn"">$($line.Preference)</td>"
					$dagsummary += "$($line.Database) - $string62 $($line.Preference)"
				}
				else
				{
					$htmltablerow += "<td class=""pass"">$($line.Preference)</td>"
				}
				
				$htmltablerow += "<td>$($line."Total Copies")</td>"
				
				#Show as info if health copies is 1 but total copies also 1,
	            #Warn if healthy copies is 1, Fail if 0
				switch ($($line."Healthy Copies"))
				{	
					0 {$htmltablerow += "<td class=""fail"">$($line."Healthy Copies")</td>"}
					1 {
						if ($($line."Total Copies") -eq $($line."Healthy Copies"))
						{
							$htmltablerow += "<td class=""info"">$($line."Healthy Copies")</td>"
						}
						else
						{
							$htmltablerow += "<td class=""warn"">$($line."Healthy Copies")</td>"
						}
					  }
					default {$htmltablerow += "<td class=""pass"">$($line."Healthy Copies")</td>"}
				}

				#Warn if unhealthy copies is 1, fail if more than 1
				switch ($($line."Unhealthy Copies"))
				{
					0 {	$htmltablerow += "<td class=""pass"">$($line."Unhealthy Copies")</td>" }
					1 {
						$htmltablerow += "<td class=""warn"">$($line."Unhealthy Copies")</td>"
						$dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
						}
					default {
						$htmltablerow += "<td class=""fail"">$($line."Unhealthy Copies")</td>"
						$dagsummary += "$($line.Database) - $string63 $($line."Unhealthy Copies") $string65 $($line."Total Copies") $string66"
						}
				}

				#Warn if healthy queues + lagged queues is less than total copies
				#Fail if no healthy queues
				if ($($line."Total Copies") -eq ($($line."Healthy Queues") + $($line."Lagged Queues")))
				{
					$htmltablerow += "<td class=""pass"">$($line."Healthy Queues")</td>"
				}
				else
				{
					$dagsummary += "$($line.Database) - $string64 $($line."Healthy Queues") $string65 $($line."Total Copies") $string66"
					switch ($($line."Healthy Queues"))
					{
						0 {	$htmltablerow += "<td class=""fail"">$($line."Healthy Queues")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Healthy Queues")</td>" }
					}
				}
				
				#Fail if unhealthy queues = total queues
				#Warn if more than one unhealthy queue
				if ($($line."Total Queues") -eq $($line."Unhealthy Queues"))
				{
					$htmltablerow += "<td class=""fail"">$($line."Unhealthy Queues")</td>"
				}
				else
				{
					switch ($($line."Unhealthy Queues"))
					{
						0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Queues")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Queues")</td>" }
					}
				}
				
				#Info for lagged queues
				switch ($($line."Lagged Queues"))
				{
					0 { $htmltablerow += "<td>$($line."Lagged Queues")</td>" }
					default { $htmltablerow += "<td class=""info"">$($line."Lagged Queues")</td>" }
				}
				
				#Pass if healthy indexes = total copies
				#Warn if healthy indexes less than total copies
				#Fail if healthy indexes = 0
				if ($($line."Total Copies") -eq $($line."Healthy Indexes"))
				{
					$htmltablerow += "<td class=""pass"">$($line."Healthy Indexes")</td>"
				}
				else
				{
					$dagsummary += "$($line.Database) - $string67 $($line."Unhealthy Indexes") $string65 $($line."Total Copies") $string66"
					switch ($($line."Healthy Indexes"))
					{
						0 { $htmltablerow += "<td class=""fail"">$($line."Healthy Indexes")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Healthy Indexes")</td>" }
					}
				}
				
				#Fail if unhealthy indexes = total copies
				#Warn if unhealthy indexes 1 or more
				#Pass if unhealthy indexes = 0
				if ($($line."Total Copies") -eq $($line."Unhealthy Indexes"))
				{
					$htmltablerow += "<td class=""fail"">$($line."Unhealthy Indexes")</td>"
				}
				else
				{
					switch ($($line."Unhealthy Indexes"))
					{
						0 { $htmltablerow += "<td class=""pass"">$($line."Unhealthy Indexes")</td>" }
						default { $htmltablerow += "<td class=""warn"">$($line."Unhealthy Indexes")</td>" }
					}
				}
				
				$htmltablerow += "</tr>"
				$dagdatabaseSummaryHtml += $htmltablerow
			}
			$dagdatabaseSummaryHtml += "</table>
									</p>"
			#End Summary table HTML rows
			####End Summary Table HTML

			####Begin Detail Table HTML
			$databasedetailsHtml = $null
			#Begin Detail table HTML header
			$htmltableheader = "<p>
							<table>
							<tr>
							<th>Database Copy</th>
							<th>Database Name</th>
							<th>Mailbox Server</th>
							<th>Activation Preference</th>
							<th>Status</th>
							<th>Copy Queue</th>
							<th>Replay Queue</th>
							<th>Replay Lagged</th>
							<th>Truncation Lagged</th>
							<th>Content Index</th>
							</tr>"

			$databasedetailsHtml += $htmltableheader
			#End Detail table HTML header
			
			#Begin Detail table HTML rows
			foreach ($line in $dagdbcopyReport)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line."Database Copy")</strong></td>"
				$htmltablerow += "<td>$($line."Database Name")</td>"
				$htmltablerow += "<td>$($line."Mailbox Server")</td>"
				$htmltablerow += "<td>$($line."Activation Preference")</td>"
				
				Switch ($($line."Status"))
				{
					"Healthy" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
					"Mounted" { $htmltablerow += "<td class=""pass"">$($line."Status")</td>" }
					"Failed" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"FailedAndSuspended" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"ServiceDown" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					"Dismounted" { $htmltablerow += "<td class=""fail"">$($line."Status")</td>" }
					default { $htmltablerow += "<td class=""warn"">$($line."Status")</td>" }
				}
				
				if ($($line."Copy Queue") -lt $replqueuewarning)
				{
					$htmltablerow += "<td class=""pass"">$($line."Copy Queue")</td>"
				}
				else
				{
					$htmltablerow += "<td class=""warn"">$($line."Copy Queue")</td>"
				}
				
				if (($($line."Replay Queue") -lt $replqueuewarning) -or ($($line."Replay Lagged") -eq $true))
				{
					$htmltablerow += "<td class=""pass"">$($line."Replay Queue")</td>"
				}
				else
				{
					$htmltablerow += "<td class=""warn"">$($line."Replay Queue")</td>"
				}
				

				Switch ($($line."Replay Lagged"))
				{
					$true { $htmltablerow += "<td class=""info"">$($line."Replay Lagged")</td>" }
					default { $htmltablerow += "<td>$($line."Replay Lagged")</td>" }
				}

				Switch ($($line."Truncation Lagged"))
				{
					$true { $htmltablerow += "<td class=""info"">$($line."Truncation Lagged")</td>" }
					default { $htmltablerow += "<td>$($line."Truncation Lagged")</td>" }
				}
				
				Switch ($($line."Content Index"))
				{
					"Healthy" { $htmltablerow += "<td class=""pass"">$($line."Content Index")</td>" }
                    "Disabled" { $htmltablerow += "<td class=""info"">$($line."Content Index")</td>" }
					default { $htmltablerow += "<td class=""warn"">$($line."Content Index")</td>" }
				}
				
				$htmltablerow += "</tr>"
				$databasedetailsHtml += $htmltablerow
			}
			$databasedetailsHtml += "</table>
									</p>"
			#End Detail table HTML rows
			####End Detail Table HTML
			
			
			####Begin Member Table HTML
			$dagmemberHtml = $null
			#Begin Member table HTML header
			$htmltableheader = "<p>
								<table>
								<tr>
								<th>Server</th>
								<th>Cluster Service</th>
								<th>Replay Service</th>
								<th>Active Manager</th>
								<th>Tasks RPC Listener</th>
								<th>TCP Listener</th>
								<th>Server Locator Service</th>
								<th>DAG Members Up</th>
								<th>Cluster Network</th>
								<th>Quorum Group</th>
								<th>File Share Quorum</th>
								<th>Database Redundancy</th>
								<th>Database Availability</th>
								<th>DB Copy Suspended</th>
								<th>DB Copy Failed</th>
								<th>DB Initializing</th>
								<th>DB Disconnected</th>
								<th>DB Log Copy Keeping Up</th>
								<th>DB Log Replay Keeping Up</th>
								</tr>"
			
			$dagmemberHtml += $htmltableheader
			#End Member table HTML header
			
			#Begin Member table HTML rows
			foreach ($line in $dagmemberReport)
			{
				$htmltablerow = "<tr>"
				$htmltablerow += "<td><strong>$($line."Server")</strong></td>"
				$htmltablerow += (New-DAGMemberHTMLTableCell "ClusterService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ReplayService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ActiveManager")
				$htmltablerow += (New-DAGMemberHTMLTableCell "TasksRPCListener")
				$htmltablerow += (New-DAGMemberHTMLTableCell "TCPListener")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ServerLocatorService")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DAGMembersUp")
				$htmltablerow += (New-DAGMemberHTMLTableCell "ClusterNetwork")
				$htmltablerow += (New-DAGMemberHTMLTableCell "QuorumGroup")
				$htmltablerow += (New-DAGMemberHTMLTableCell "FileShareQuorum")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseRedundancy")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DatabaseAvailability")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBCopySuspended")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBCopyFailed")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBInitializing")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBDisconnected")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBLogCopyKeepingUp")
				$htmltablerow += (New-DAGMemberHTMLTableCell "DBLogReplayKeepingUp")
				$htmltablerow += "</tr>"
				$dagmemberHtml += $htmltablerow
			}
			$dagmemberHtml += "</table>
			</p>"
		}
		
		#Output the report objects to console, and optionally to email and HTML file
		#Forcing table format for console output due to issue with multiple output
		#objects that have different layouts

		#Write-Host "---- Database Copy Health Summary ----"
		#$dagdatabaseSummary | ft
				
		#Write-Host "---- Database Copy Health Details ----"
		#$dagdbcopyReport | ft
		
		#Write-Host "`r`n---- Server Test-Replication Report ----`r`n"
		#$dagmemberReport | ft
		
		if ($SendEmail -or $ReportFile)
		{
			$dagreporthtml = $dagsummaryintro + $dagdatabaseSummaryHtml + $dagdetailintro + $databasedetailsHtml + $dagmemberintro + $dagmemberHtml
			$dagreportbody += $dagreporthtml
		}
		
	}
}
else
{
	$tmpstring = "No DAGs found"
	if ($Log) {Write-LogFile $tmpstring}
	Write-Verbose $tmpstring
	$dagreporthtml = "<p>No database availability groups found.</p>"
}
### End DAG Health Report

### Begin Collect Clients Connections Statistics
$tmpstring = "Collect Clients Connections Statistics"
Write-Verbose $tmpstring

if ($Log) {Write-LogFile $tmpstring}

$ConnectionsStatistics=@()

$clientaccessservers= $exchangeservers | Get-ExchangeServer | where {$_.ServerRole -like "*Client*"} | Sort-Object Name
$clientaccessserverscount = ($clientaccessservers | measure).count

if($clientaccessserverscount -gt 0)
{
    foreach ($srv in $clientaccessservers)
    {
		$tmpstring = "Collecting data for $($srv)"
		Write-Verbose $tmpstring
        
        if ($Log) {Write-LogFile $tmpstring}
    
        $row=New-Object -TypeName PSObject
		$row | Add-Member -MemberType NoteProperty -Name "Server" -Value $Srv.Name
		$counter=Get-Counter "\MSExchange RpcClientAccess\User Count" -ComputerName $srv.Name
		$row | Add-Member -MemberType NoteProperty -Name "RpcClientAccess" -Value $counter.CounterSamples[0].CookedValue
        $counter=Get-Counter "\MSExchange OWA\Current Unique Users" -ComputerName $srv.Name
		$row | Add-Member -MemberType NoteProperty -Name "Current Unique OWA Users" -Value $counter.CounterSamples[0].CookedValue
        $counter=Get-Counter "\MSExchange ActiveSync\Current Requests" -ComputerName $srv.Name
		$row | Add-Member -MemberType NoteProperty -Name "Current ActiveSync Requests" -Value $counter.CounterSamples[0].CookedValue
        
        $ConnectionsStatistics+=$row
	}
}
    

### End Collect Client Statistics

if ($ConnectionsStatistics.Count -gt 0) {
    
    $statisticshtmltableheader = `
    "<p>Client Connectivity Statistics:</p>
	<p>
	<table>
	<tr>
	<th>Server</th>
	<th>RpcClientAccess</th>
	<th>Current Unique OWA Users</th>
	<th>Current ActiveSync Requests</th>
	</tr>"
	
	$statisticshtml += $statisticshtmltableheader
   
    foreach ($stat in $ConnectionsStatistics){
		$statisticshtmlrow = "<tr>"
		$statisticshtmlrow += "<td>$($stat.server)</td>"

		if($stat."RpcClientAccess" -lt $cascurrentrequestswarn){
			$statisticshtmlrow += "<td class=""pass"">$($stat."RpcClientAccess")</td>"
		} elseif($stat."RpcClientAccess" -gt $cascurrentrequestshigh) {
			$statisticshtmlrow += "<td class=""fail"">$($stat."RpcClientAccess")</td>"
			$statisticssummary += "$($stat.server) - Amount of RPC Client Access Users is too high."
		} else {
			$statisticshtmlrow += "<td class=""warn"">$($stat."RpcClientAccess")</td>"
			$statisticssummary += "$($stat.server) - Amount of RPC Client Access Users is too high."
		}

		if($stat."Current Unique OWA Users" -lt $cascurrentrequestswarn){
			$statisticshtmlrow += "<td class=""pass"">$($stat."Current Unique OWA Users")</td>"
		} elseif($stat."Current Unique OWA Users" -gt $cascurrentrequestshigh) {
			$statisticshtmlrow += "<td class=""fail"">$($stat."Current Unique OWA Users")</td>"
			$statisticssummary += "$($stat.server) - Amount of Current Unique OWA Users is too high."
		} else {
			$statisticshtmlrow += "<td class=""warn"">$($stat."Current Unique OWA Users")</td>"
			$statisticssummary += "$($stat.server) - Amount of Current Unique OWA Users is too high."
		}

		if($stat."Current ActiveSync Requests" -lt $cascurrentrequestswarn){
		$statisticshtmlrow += "<td class=""pass"">$($stat."Current ActiveSync Requests")</td>"
		} elseif($stat."Current ActiveSync Requests" -gt $cascurrentrequestshigh) {
			$statisticshtmlrow += "<td class=""fail"">$($stat."Current ActiveSync Requests")</td>"
			$statisticssummary += "$($stat.server) - Amount of Current ActiveSync Requests is too high."
		} else {
			$statisticshtmlrow += "<td class=""warn"">$($stat."Current ActiveSync Requests")</td>"
			$statisticssummary += "$($stat.server) - Amount of Current ActiveSync Requests is too high."
		}					
		$statisticshtmlrow += "</tr>"

		$statisticshtml += $statisticshtmlrow
	}
	$statisticshtml += "</table></p>"
}
else {
    $statisticshtml = "<p>No Client Connectivity Statistics available</p>"
}


###
Write-Host $string16
### Begin report generation
if ($ReportMode -or $SendEmail)
{
	#Get report generation timestamp
	$reportime = Get-Date

	#Create HTML Report
	#Common HTML head and styles
	$htmlhead="<html>
				<style>
				BODY{font-family: Arial; font-size: 8pt;}
				H1{font-size: 16px;}
				H2{font-size: 14px;}
				H3{font-size: 12px;}
				TABLE{border: 1px solid black; border-collapse: collapse; font-size: 8pt;}
				TH{border: 1px solid black; background: #dddddd; padding: 5px; color: #000000;}
				TD{border: 1px solid black; padding: 5px; }
				td.pass{background: #7FFF00;}
				td.warn{background: #FFE600;}
				td.fail{background: #FF0000; color: #ffffff;}
				td.info{background: #85D4FF;}
				</style>
				<body>
				<h1 align=""center"">Exchange Server Health Check Report</h1>
				<h3 align=""center"">Generated: $reportime</h3>"

	#Check if the server summary has 1 or more entries
	if ($($serversummary.count) -gt 0)
	{
		#Set alert flag to true
		$alerts = $true
	
		#Generate the HTML
		$serversummaryhtml = "<h3>Exchange Server Health Check Summary</h3>
						<p>The following server errors and warnings were detected.</p>
						<p>
						<ul>"
		foreach ($reportline in $serversummary)
		{
			$serversummaryhtml +="<li>$reportline</li>"
		}
		$serversummaryhtml += "</ul></p>"
		$alerts = $true
	}
	else
	{
		#Generate the HTML to show no alerts
		$serversummaryhtml = "<h3>Exchange Server Health Check Summary</h3>
						<p>No Exchange server health errors or warnings.</p>"
	}
	
	#Check if the DAG summary has 1 or more entries
	if ($($dagsummary.count) -gt 0)
	{
		#Set alert flag to true
		$alerts = $true
	
		#Generate the HTML
		$dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
						<p>The following DAG errors and warnings were detected.</p>
						<p>
						<ul>"
		foreach ($reportline in $dagsummary)
		{
			$dagsummaryhtml +="<li>$reportline</li>"
		}
		$dagsummaryhtml += "</ul></p>"
		$alerts = $true
	}
	else
	{
		#Generate the HTML to show no alerts
		$dagsummaryhtml = "<h3>Database Availability Group Health Check Summary</h3>
						<p>No Exchange DAG errors or warnings.</p>"
	}

	#Check if Client Connectivity Statistics summary
	if($($statisticssummary.count) -gt 0)
	{
		#Set alert flag to true
		$alerts = $true
	
		#Generate the HTML
		$statisticssummaryhtml = "<h3>Client Connectivity Statistics Summary</h3>
						<p>The following Client Connectivity Statistics errors and warnings were detected.</p>
						<p>
						<ul>"
		foreach ($reportline in $statisticssummary)
		{
			$statisticssummaryhtml +="<li>$reportline</li>"
		}
		$statisticssummaryhtml += "</ul></p>"
		$alerts = $true
	} else
	{
		#Generate the HTML to show no alerts
		$statisticssummaryhtml = "<h3>Client Connectivity Statistics Summary</h3>
						<p>No Client Connectivity Statistics errors or warnings.</p>"
	}

	#Exchange Server Health Report Table Header
	$htmltableheader = "<h3>Exchange Server Health</h3>
						<p>
						<table>
						<tr>
						<th>Server</th>
						<th>Site</th>
						<th>Roles</th>
						<th>Version</th>
						<th>DNS</th>
						<th>Ping</th>
						<th>Uptime (hrs)</th>
						<th>Client Access Server Role Services</th>
						<th>Hub Transport Server Role Services</th>
						<th>Mailbox Server Role Services</th>
						<th>Unified Messaging Server Role Services</th>
						<th>Transport Queue</th>
						<th>PF DBs Mounted</th>
						<th>MB DBs Mounted</th>
						<th>MAPI Test</th>
						<th>Mail Flow Test</th>
						</tr>"

	#Exchange Server Health Report Table
	$serverhealthhtmltable = $serverhealthhtmltable + $htmltableheader					
						
	foreach ($reportline in $report)
	{
		$htmltablerow = "<tr>"
		$htmltablerow += "<td>$($reportline.server)</td>"
		$htmltablerow += "<td>$($reportline.site)</td>"
		$htmltablerow += "<td>$($reportline.roles)</td>"
		$htmltablerow += "<td>$($reportline.version)</td>"					
		$htmltablerow += (New-ServerHealthHTMLTableCell "dns")
		$htmltablerow += (New-ServerHealthHTMLTableCell "ping")
		
		if ($($reportline."uptime (hrs)") -eq "Access Denied")
		{
			$htmltablerow += "<td class=""warn"">Access Denied</td>"		
		}
        elseif ($($reportline."uptime (hrs)") -eq $string17)
        {
            $htmltablerow += "<td class=""warn"">$string17</td>"
        }
		else
		{
			$hours = [int]$($reportline."uptime (hrs)")
			if ($hours -le 24)
			{
				$htmltablerow += "<td class=""warn"">$hours</td>"
			}
			else
			{
				$htmltablerow += "<td class=""pass"">$hours</td>"
			}
		}

		$htmltablerow += (New-ServerHealthHTMLTableCell "Client Access Server Role Services")
		$htmltablerow += (New-ServerHealthHTMLTableCell "Hub Transport Server Role Services")
		$htmltablerow += (New-ServerHealthHTMLTableCell "Mailbox Server Role Services")
		$htmltablerow += (New-ServerHealthHTMLTableCell "Unified Messaging Server Role Services")
		#$htmltablerow += (New-ServerHealthHTMLTableCell "Transport Queue")
        if ($($reportline."Transport Queue") -match "Pass")
        {
            $htmltablerow += "<td class=""pass"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -match "Warn")
        {
            $htmltablerow += "<td class=""warn"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -match "Fail")
        {
            $htmltablerow += "<td class=""fail"">$($reportline."Transport Queue")</td>"
        }
        elseif ($($reportline."Transport Queue") -eq "n/a")
        {
            $htmltablerow += "<td>$($reportline."Transport Queue")</td>"
        }
        else
        {
            $htmltablerow += "<td class=""warn"">$($reportline."Transport Queue")</td>"
        }
		$htmltablerow += (New-ServerHealthHTMLTableCell "PF DBs Mounted")
		$htmltablerow += (New-ServerHealthHTMLTableCell "MB DBs Mounted")
		$htmltablerow += (New-ServerHealthHTMLTableCell "MAPI Test")
		$htmltablerow += (New-ServerHealthHTMLTableCell "Mail Flow Test")
		$htmltablerow += "</tr>"
		
		$serverhealthhtmltable = $serverhealthhtmltable + $htmltablerow
	}

	$serverhealthhtmltable = $serverhealthhtmltable + "</table></p>"

	$htmltail = "</body>
				</html>"

	$htmlreport = $htmlhead + $serversummaryhtml + $dagsummaryhtml + $statisticssummaryhtml + $serverhealthhtmltable + $dagreportbody + $statisticshtml + $htmltail
	if ($ReportMode -or $ReportFile)
	{
		$htmlreport | Out-File $ReportFile -Encoding UTF8
	}

	if ($SendEmail)
	{
		if ($alerts -eq $false -and $AlertsOnly -eq $true)
		{
			#Do not send email message
			Write-Host $string19
			if ($Log) {Write-Logfile $string19}
		}
		else
		{
			#Send email message
			Write-Host $string14
			Send-MailMessage @smtpsettings -Body $htmlreport -BodyAsHtml -Encoding ([System.Text.Encoding]::UTF8)
		}
	}
}
### End report generation


Write-Host $string15
if ($Log) {Write-Logfile $string15}

