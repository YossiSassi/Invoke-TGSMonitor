# Comments welcome to yossis@protonmail.com (1nTh35h311)
# Monitor TGS requests with Error code reasons. Useful during a live IR without other central threat hunting log solution, or in general, to detect authentication failure reasons.
# Requires 'Event Log Redears' permission or equivalent (preferrably - run elevated on the PDC/one of the DCs, for better Performance and continued operation of the monitoring process).
# Note: Auditing for 'Kerberos Service Ticket Operations' must be Enabled for both Failure & Success. Check using the following command: auditpol /get /category:'Account Logon' /r | ConvertFrom-Csv | where Subcategory -like "*Kerberos*" | Format-Table 'Policy Target',Subcategory,'Inclusion Setting'

<# TIP: for 'Real time monitor': 
cat c:\temp\TGSMonitor.csv -Tail 0 -Wait
- Or - Monitor for a specific user (run with -LogAllTickets) and display in a nice table:
while ($true) {$x=cat .\temp\TGSMonitor.csv | ConvertFrom-Csv;cls;$x| ? account -like "*yossis*" | ft -AutoSize; sleep 1}
#>

<# TIP 2: for potential golden ticket 'real time monitor': 
while ($true) {get-date;$x=import-csv .\TGSMonitor.csv" |select -ExpandProperty ErrorCode -Unique;if ($x|sls 0x1f) {write-warning "0x1f detected!"};$x;sleep 30}
#while ($true) {get-date;$y=import-csv .\TGSMonitor.csv";$x= $y |select -ExpandProperty ErrorCode -Unique;if ($x|sls 0x1f) {write-warning "0x1f detected!"};$y | group ErrorCode |select name, count|sort count -Descending| ft -AutoSize;sleep 30}
#>

<#
.PARAMETER LogAllTickets
When specified, this switch will enable logging of all TGS tickets, both success & failure (full access log).

.EXAMPLE
.\Invoke-TGSMonitor.ps1
Runs the tgs monitor with default options, logging Failed TGS events only (potentially suspicious access requests).

.EXAMPLE
while ($true) {$x=cat .\temp\TGSMonitor.csv | ConvertFrom-Csv;cls;$x| ? account -like "*yossis*" | ft -AutoSize; sleep 1}
When this script is running in the background, running this command will display a 'real-time monitor' with a table containing the TGS events generated from this specific user, in this case, YOSSIS.
#>

param (
    [cmdletbinding()]
    [switch]$LogAllTickets
)

$ErrorActionPreference = "SilentlyContinue";
$version = "1.0";

[datetime]$KrbTgtResetDate = [datetime]::FromFileTime($(([adsisearcher]"samaccountname=krbtgt").FindOne().Properties.pwdlastset));

$Logo = @"
___________________  _________     _____                .__  __                
\__    ___/  _____/ /   _____/    /     \   ____   ____ |__|/  |_  ___________ 
  |    | /   \  ___ \_____  \    /  \ /  \ /  _ \ /    \|  \   __\/  _ \_  __ \
  |    | \    \_\  \/        \  /    Y    (  <_> )   |  \  ||  | (  <_> )  | \/
  |____|  \______  /_______  /  \____|__  /\____/|___|  /__||__|  \____/|__|   
                 \/        \/           \/            \/                       

  by 1nTh35h311 (#Yossi_Sassi) v$version
"@

$Logo;

$Host.UI.RawUI.WindowTitle = "!! TGS Monitor !! <Last KRBTGT Reset: $KrbTgtResetDate>"
Write-Host "`n[x] Last KRBTGT Reset: $KrbTgtResetDate." -ForegroundColor Cyan;

if ($LogAllTickets)
    {
        Write-Host "`[!] Logging ALL tickets, success and failure (FULL LOG to CSV)" -ForegroundColor Yellow;
    }
else
    {
        Write-Host "`[!] Logging failure/suspicious tickets only." -ForegroundColor Yellow;
    }

$Logfile = "$(Get-Location)\TGSMonitor.csv";

# if 1st time, create CSV file and headers
if (!(Test-Path $Logfile)) {
    $null = New-Item $Logfile -ItemType File -Force;
    '"IPAddress","ComputerName","TimeCreated","Account","AccountDomain","ServiceName","ServiceSID","TicketOptions","TicketEncryptionType","Port","ErrorCode","ErrorCodeReason","LogonGUID","TransmittedServices"' | Out-File $Logfile -Encoding utf8
}

$DCs = ([adsisearcher]"(&(objectCategory=computer)(|(primarygroupid=521)(primarygroupid=516)))").FindAll().Properties.name;

$regex = '\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b' # for IPv4 matches

while ($true) {
$FilteredEvents = @();

$DCs | foreach {
	$DC = $_;
    write-host "[x] Fetching TGS events from $DC..." -ForegroundColor Cyan;
    $Events = Get-WinEvent -FilterHashtable @{logname='Security';id=4769;StartTime=$KrbTgtResetDate} -ComputerName $DC;
    # notify on error(s), if encountered
    if (!$?) {"[x] $(Get-Date): $($error[0].Exception.Message) <DC: $DC>"}
    
    # check if last recordID was set, or initial query
    if (Get-Variable $($DC+"_LastRecordId")) {
            $FilteredEvents += $Events | where recordID -gt $((Get-Variable $($DC+"_LastRecordId")).Value);
        }
    else
        {
            New-Variable $($DC+"_LastRecordId");
            $FilteredEvents += $Events;
        }
    Set-Variable $($DC+"_LastRecordId") -Value $Events[0].RecordId;
    Clear-Variable Events;
    }

Write-Host "[x] $(Get-Date): Collected $($FilteredEvents.count) Events (since last checkpoint)." -ForegroundColor green;

if (!$LogAllTickets) {
        # Filter by failed TGS only
        $AuditTGS = $FilteredEvents | where keywordsDisplayNames -eq "Audit Failure" #keywords="-9218868437227405312"
    }
else # all TGS, inc. success
    {
        $AuditTGS = $FilteredEvents;
    }

if ($AuditTGS) {
    $AuditTGS | foreach { 
        $Event = $_;
                if ($Event.KeywordsDisplayNames -eq "Audit Failure") {Write-Host "`n[x] Failed TGS Found (potential suspicious TGS)" -ForegroundColor Red}
                $IPAddress = ([xml]($Event.ToXml())).event.eventdata.data.'#text'[6];
                $ComputerName = (Resolve-DnsName ($IPAddress | sls -Pattern $regex).Matches.Value).nameHost
                $TimeCreated = $($Event.TimeCreated)
                $TargetUserName = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[0])
                $TargetDomainName = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[1])
                $ServiceName = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[2])
                $ServiceSID = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[3])
                $TicketOptions = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[4])
                $TicketEncryptionType = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[5])
                $Port = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[7])
                $ErrorCode = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[8])
                $LogonGUID = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[9])
                $TransmittedServices = $(([xml]($Event.ToXml())).event.eventdata.data.'#text'[10])

                # Match TGS failure code to reason
                Switch ($ErrorCode)
                    {
                        '0x1'	{$ErrorCodeReason = "Client's entry in database has expired"}
                        '0x2'	{$ErrorCodeReason = "Server's entry in database has expired"}
                        '0x3'	{$ErrorCodeReason = "Requested protocol version not supported"}
                        '0x4'	{$ErrorCodeReason = "Client's key encrypted in old master key"}
                        '0x5'	{$ErrorCodeReason = "Server's key encrypted in old master key"}
                        '0x6'	{$ErrorCodeReason = "Client not found in KRB DB: Bad UserName/New computer/account not replicated to DC yet"}
                        '0x7'	{$ErrorCodeReason = "Client not found in KRB DB: Bad UserName/computer not replicated to DC yet, or Pre-W2K"}
                        '0x8'	{$ErrorCodeReason = "Multiple principal entries in database"}
                        '0x9'	{$ErrorCodeReason = "The client or server has a null key: administrator should reset the password for the account"}
                        '0xA'	{$ErrorCodeReason = "Ticket not eligible for postdating"}
                        '0xB'	{$ErrorCodeReason = "Requested start time is later than end time"}
                        '0xC'	{$ErrorCodeReason = "KDC policy rejects request	Workstation restriction"}
                        '0xD'	{$ErrorCodeReason = "KDC cannot accommodate requested option"}
                        '0xE'	{$ErrorCodeReason = "KDC has no support for encryption type"}
                        '0xF'	{$ErrorCodeReason = "KDC has no support for checksum type"}
                        '0x10'	{$ErrorCodeReason = "KDC has no support for padata type"}
                        '0x11'	{$ErrorCodeReason = "KDC has no support for transited type"}
                        '0x12'	{$ErrorCodeReason = "Clients credentials have been revoked: Account disabled, expired, locked out, logon hours"}
                        '0x13'	{$ErrorCodeReason = "Credentials for server have been revoked"}	 
                        '0x14'	{$ErrorCodeReason = "TGT has been revoked"}
                        '0x15'	{$ErrorCodeReason = "Client not yet valid - try again later"}
                        '0x16'	{$ErrorCodeReason = "Server not yet valid - try again later"}
                        '0x17'	{$ErrorCodeReason = "Password has expired/The user’s password has expired"}
                        '0x18'	{$ErrorCodeReason = "Pre-authentication information was invalid. Usually means bad password"}
                        '0x19'	{$ErrorCodeReason = "Additional pre-authentication required. May occur with Unix-Interop/Pre-authN not sent/may be ignored if WinHost"}
                        '0x1a'	{$ErrorCodeReason = "KDC does not know about the requested server"}
                        '0x1b'	{$ErrorCodeReason = "KDC is Unavailable"}
                        '0x1F'	{$ErrorCodeReason = "Integrity check on decrypted field failed <POTENTIAL GOLDEN TICKET>"}
                        '0x20'	{$ErrorCodeReason = "Ticket expired. Frequently logged by computer accounts"}
                        '0x21'	{$ErrorCodeReason = "Ticket not yet valid"}
                        '0x21'	{$ErrorCodeReason = "Ticket not yet valid"}
                        '0x22'	{$ErrorCodeReason = "Request is a replay"}
                        '0x23'	{$ErrorCodeReason = "The ticket isn't for us"}
                        '0x24'	{$ErrorCodeReason = "Ticket and authenticator don't match"}
                        '0x25'	{$ErrorCodeReason = "Clock skew too great. Workstation’s clock too far out of sync with the DC's"}
                        '0x26'	{$ErrorCodeReason = "Incorrect net address. Possible IP address change?"}
                        '0x27'	{$ErrorCodeReason = "Protocol version mismatch"}
                        '0x28'	{$ErrorCodeReason = "Invalid msg type"}
                        '0x29'	{$ErrorCodeReason = "Message stream modified"}
                        '0x2A'	{$ErrorCodeReason = "Message out of order"}
                        '0x2C'	{$ErrorCodeReason = "Specified version of key is not available"}
                        '0x2D'	{$ErrorCodeReason = "Service key not available"}
                        '0x2E'	{$ErrorCodeReason = "Mutual authentication failed. may be a memory allocation failure"}
                        '0x2F'	{$ErrorCodeReason = "Incorrect message direction"}
                        '0x30'	{$ErrorCodeReason = "Alternative authentication method required. Obselete, according to RFC4210"}
                        '0x31'	{$ErrorCodeReason = "Incorrect sequence number in message"}
                        '0x32'	{$ErrorCodeReason = "Inappropriate type of checksum in message"}
                        '0x3C'	{$ErrorCodeReason = "Generic error (description in e-text)"}
                        '0x3D'	{$ErrorCodeReason = "Field is too long for this implementation"}
                        default {$ErrorCodeReason = "none specified"}
                }

                Write-Host "IP Address: $IPAddress (ComputerName: $ComputerName)" -ForegroundColor Yellow
                Write-Host "Time Created: $($Event.TimeCreated)" -ForegroundColor Yellow
                Write-Host "Account: $TargetUserName"
                Write-Host "AccountDomain: $TargetDomainName"
                Write-Host "ServiceName: $ServiceName"
                Write-Host "ServiceSID: $ServiceSID"
                Write-Host "TicketOptions: $TicketOptions"
                Write-Host "TicketEncryptionType: $TicketEncryptionType"
                Write-Host "Port: $Port"
                Write-Host "Error Code: $ErrorCode <$ErrorCodeReason>" -ForegroundColor Yellow
                Write-Host "Logon GUID: $LogonGUID"
                Write-Host "TransmittedServices: $TransmittedServices`n"

                # write to log file
                """$IPAddress"",""$ComputerName"",""$TimeCreated"",""$TargetUserName"",""$TargetDomainName"",""$ServiceName"",""$ServiceSID"",""$TicketOptions"",""$TicketEncryptionType"",""$Port"",""$ErrorCode"",""$ErrorCodeReason"",""$LogonGUID"",""$TransmittedServices""" | Out-File -FilePath $Logfile -Encoding utf8 -Append
                
                Clear-Variable IPAddress, ComputerName, Timecreated, TargetUserName, TargetDomainName,ServiceName,ServiceSID,TicketOptions,TicketEncryptionType,Port,ErrorCode,LogonGUID,TransmittedServices,ErrorCodeReason
    }
  }
  Write-Host "[x] Finished looking for TGS events on all DCs. WAITING FOR NEXT CHECK/LOOP." -ForegroundColor Magenta;
  Write-Host "[!] To quit, Press CTRL+C. Check " -ForegroundColor Yellow -NoNewline; Write-Host  $Logfile -ForegroundColor Cyan -NoNewline; Write-Host " to see tickets log file." -ForegroundColor Yellow;

  # free up memory
  Clear-Variable FilteredEvents;
  [gc]::Collect();

  # sleep for xx seconds, and loop again
  sleep -Seconds 20
}