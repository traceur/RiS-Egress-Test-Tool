# RiS-Egress-Test.ps2  (Windows Version)

# 20150209 kevin@rawinfosec.com

# Usage:
# 	powershell.exe -ExecutionPolicy Bypass -File "c:\foldername\test.ps1"

# Client side tool to determine if the currently connected network is blocking a set of ports commonly used to exploit network devices from inside the firewall.

# This tool connects to egress.rawinfosec.com. You can change this in the source to a server of your choice. We have configured and made available this server
#      for the time being but do not warranty availability in the future.
# This tool does not send any of your data to our server. It simply attempts to create the initial TCP connections.
# Ports tested are as per SANS Egress Filtering FAQ plus a couple RawInfoSec feel should be added.  We have not yet implemented UDP tests.
#      SANS PDF - https://www.sans.org/reading-room/whitepapers/firewalls/egress-filtering-faq-1059?show=egress-filtering-faq-1059&cat=firewalls

# Copyright (C) 2015 RawInfoSec.com

# Author: Kevin Creechan     @RawInfoSec     kevin@rawinfosec.com
# Version: 1.0 (20150125-1)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.



Write-Host "`n`n`nRiS-Egress-Test Tool v1.0"
Write-Host "`nCopyright (C) 2015 RawInfoSec.com          @RawInfoSec"

$hostaddr="egress.rawinfosec.com"
Write-Host "`n`n`nUsing server: $hostaddr "


$portlist=@{}
$portlist[21] = @{}
$portlist[21]["name"] ="FTP"
$portlist[21]["open"] ="Most malware will exfiltrate data from your network by some means. One of the most common means is via an FTP connection to an external server.  Allowing FTP traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)\n( more http://www.speedguide.net/port.php?port=21 )"
$portlist[21]["blocked"] = "Most common malware will exfiltrate data from your network by some means. FTP is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server.\n( more http://www.speedguide.net/port.php?port=21 )"
$portlist[25] = @{}
$portlist[25]["name"] ="SMTP"
$portlist[25]["open"] ="One of the most common things that Malware does is send SPAM. Workstations on an internal network should only be able to connect to either an internal mail server or have your firewall limit outbound SMTP traffic to a known external server.  By allowing outbound SMTP traffic, you risk having your public IP address blacklisted and unable to send legit email from an internal email server.  You may also be asked by your ISP to halt the traffic or face disconnection if the traffic is persistent enough.\n( more http://www.speedguide.net/port.php?port=25 )"
$portlist[25]["blocked"] = "One of the most common things that Malware does is send SPAM. Workstations on an internal network should only be able to connect to either an internal mail server or have your firewall limit outbound SMTP traffic to a known external server.  Having blocked this port, you are protected from having your IP address blacklisted and unable to send legit mail, or even an ISP threatening to shut you down.\n( more http://www.speedguide.net/port.php?port=25 )"
$portlist[53] = @{}
$portlist[53]["name"] ="DNS"
$portlist[53]["open"] ="DNS is a required process for network connectivity. That said, good practice is to have an internal DNS server and require all workstations to use that instead of an ISP or public (eg Google) server. By allowing DNS requests to leave your network you are at risk of allowing an attacker to control DNS resolution and subsequently forcing internal workstations to visit servers hosting more malicious content. Only your internal DNS server should be allowed to successfully connect on outbound port 53.\n( more http://www.speedguide.net/port.php?port=53 )"
$portlist[53]["blocked"] = "DNS is a required process for network connectivity. That said, good practice is to have an internal DNS server and require all workstations to use that instead of an ISP or public (eg Google) server. This prevents DNS poisoning attacks and having your workstations forced to visit malicious servers by mistake.\n( more http://www.speedguide.net/port.php?port=53 )"
$portlist[123] = @{}
$portlist[123]["name"] ="NTP"
$portlist[123]["open"] ="This port is used to sync time with a remote time server.  It is best to have one internal time server with access to the outside, while all other network devices are forced to only use that for syncing time.  Allowing outside NTP access to workstations can be combined with a DNS poisoning attack to force these devices to obtain the wrong time from a malicious external server. This leads to many issues with some authentication platforms such as Microsoft Active Directory based Windows domain logins. (basically a denial-of-service attack). This port should always be blocked with an exception created for only your internal time server to communicate with a known time server like NIST.\n( more http://www.speedguide.net/port.php?port=123 )"
$portlist[123]["blocked"] = "This port is used to sync time with a remote time server.  It is best to have one internal time server with access to the outside, while all other network devices are forced to only use that for syncing time.  Having proper time syncing across a network helps with debugging network logs, but more importantly it is required some some types of authentication such as Windows domain logins.\n( more http://www.speedguide.net/port.php?port=123 )"
$portlist[135] = @{}
$portlist[135]["name"] ="RPC"
$portlist[135]["open"] ="This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=135 )"
$portlist[135]["blocked"] = "This port is used by Windows sub-systems for cross LAN operations.  Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=135 )"
$portlist[137] = @{}
$portlist[137]["name"] ="NETBIOS"
$portlist[137]["open"] ="This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=137 )"
$portlist[137]["blocked"] = "This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=137 )"
$portlist[138] = @{}
$portlist[138]["name"] ="NETBIOS"
$portlist[138]["open"] ="This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=138 )"
$portlist[138]["blocked"] = "This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=138 )"
$portlist[139] = @{}
$portlist[139]["name"] ="NETBIOS"
$portlist[139]["open"] ="This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=139 )"
$portlist[139]["blocked"] = "This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=139 )"
$portlist[445] = @{}
$portlist[445]["name"] ="AD/SMB"
$portlist[445]["open"] ="This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=445 )"
$portlist[445]["blocked"] = "This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=445 )"
$portlist[6665] = @{}
$portlist[6665]["name"] ="IRC-5"
$portlist[6665]["open"] ="Most malware will exfiltrate data from your network by some means. One of the most common means is via an IRC connection to an external server.  Allowing IRC traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)  You are also at risk from having workstations harvested as part of a bot-net in which IRC serves as command and control.  This port needs to be blocked in order to mitigate most of these common threat-types.\n( more http://www.speedguide.net/port.php?port=6665 )"
$portlist[6665]["blocked"] = "Most common malware will exfiltrate data from your network by some means. IRC is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server. IRC is also commonly used to Command & Control many exploited machines known as a bot-net.  Blocking this port also helps prevent an attacker from roaming free within your network.\n( more http://www.speedguide.net/port.php?port=6665 )"
$portlist[6667] = @{}
$portlist[6667]["name"] ="IRC-7"
$portlist[6667]["open"] ="Most malware will exfiltrate data from your network by some means. One of the most common means is via an IRC connection to an external server.  Allowing IRC traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)  You are also at risk from having workstations harvested as part of a bot-net in which IRC serves as command and control.  This port needs to be blocked in order to mitigate most of these common threat-types.\n( more http://www.speedguide.net/port.php?port=6667 )"
$portlist[6667]["blocked"] = "Most common malware will exfiltrate data from your network by some means. IRC is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server. IRC is also commonly used to Command & Control many exploited machines known as a bot-net.  Blocking this port also helps prevent an attacker from roaming free within your network.\n( more http://www.speedguide.net/port.php?port=6667 )"



function EgressTest($testport){  	
        $Socket = New-Object System.Net.Sockets.TCPClient
	$connect = $Socket.BeginConnect($hostaddr,$testport,$null,$null)
	$wait = $connect.AsyncWaitHandle.WaitOne(2000,$false) 
	If (!$wait) {
 	  $Socket.Close() | out-Null
 	  return $false
	} Else {
 	  $Socket.Close() | out-Null 
  	  return $true
	}	
}


foreach ($h in $portlist.Keys) {
	Write-Host -NoNewline "`n`n`nTesting $($portlist[${h}].name) Port ${h}.......";
	if (EgressTest(${h})) {
		  Write-Host -NoNewline -foregroundcolor "yellow" -backgroundcolor "darkred" "$($portlist[${h}].name) is OPEN!."
		  Write-Host "`n`n$($portlist[${h}].open)"
	} else {
		  Write-Host -NoNewline -foregroundcolor "white" -backgroundcolor "darkgreen" "$($portlist[${h}].name) is BLOCKED!"
		  Write-Host "`n`n$($portlist[${h}].blocked)"
	}
}


Write-Host "`n`n`n`n"
Read-Host "Press any key to close window"

