# Invoke-TGSMonitor
Monitor TGS requests (All, or just Failed ones, with Error Code reasons). Useful during a live IR without other central threat hunting log solution, or in general, to monitor access &amp; failure reasons

Requires 'Event Log Readers' permission or equivalent (preferably - run elevated on the PDC/one of the DCs, for better Performance and continued operation of the monitoring process).

Note: Auditing for 'Kerberos Service Ticket Operations' must be Enabled for both Failure & Success. Check using the following command: 

auditpol /get /category:'Account Logon' /r | ConvertFrom-Csv | where Subcategory -like "*Kerberos*" | Format-Table 'Policy Target',Subcategory,'Inclusion Setting'


.PARAMETER LogAllTickets

When specified, this switch will enable logging of all TGS tickets, both success & failure (full access log). by defauly, only FAILED TGS are logged.



Monitoring a specific account:

When this script is running in the background, running the following command in a separate window will display a 'real-time monitor' with a table containing the TGS events generated from specific user, computer, status etc. in this case, filtered by account named YOSSIS:

while ($true) {$x=cat .\temp\TGSMonitor.csv | ConvertFrom-Csv;cls;$x| ? account -like "* yossis *" | ft -AutoSize; sleep 1}

Comments welcome to yossis@protonmail.com (1nTh35h311)
