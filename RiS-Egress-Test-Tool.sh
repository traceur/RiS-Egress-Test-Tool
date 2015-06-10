#!/usr/bin/perl

# RiS-Egress-Test.pl

# 20150209 kevin@rawinfosec.com

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


use IO::Socket::INET;

$host="egress.rawinfosec.com"; 		#   ******** SET HOST HERE!


sub testport{ 
	# auto-flush on socket
	#$| = 1;
	my $port=@_[0];
	
	my $socket = new IO::Socket::INET (
		Timeout => 1000,  
		PeerHost => $host,
		PeerPort => $port,
		Proto => 'tcp',
	);
	unless ($socket) {
		$ret = 0;
	} else {
		shutdown($socket, 1);
        	$socket->close();
		$ret = 1;
	}
	return $ret;
}


# port definitions format =   ('port#' => ["portname", "text if blocked", "text if open"])

%portdefs= (
	'21' => [
		"FTP",
		"Most common malware will exfiltrate data from your network by some means. FTP is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server.\n( more http://www.speedguide.net/port.php?port=21 )",
		"Most malware will exfiltrate data from your network by some means. One of the most common means is via an FTP connection to an external server.  Allowing FTP traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)\n( more http://www.speedguide.net/port.php?port=21 )"
	],
	'25' => [
		"SMTP",
		"One of the most common things that Malware does is send SPAM. Workstations on an internal network should only be able to connect to either an internal mail server or have your firewall limit outbound SMTP traffic to a known external server.  Having blocked this port, you are protected from having your IP address blacklisted and unable to send legit mail, or even an ISP threatening to shut you down.\n( more http://www.speedguide.net/port.php?port=25 )",
		"One of the most common things that Malware does is send SPAM. Workstations on an internal network should only be able to connect to either an internal mail server or have your firewall limit outbound SMTP traffic to a known external server.  By allowing outbound SMTP traffic, you risk having your public IP address blacklisted and unable to send legit email from an internal email server.  You may also be asked by your ISP to halt the traffic or face disconnection if the traffic is persistent enough.\n( more http://www.speedguide.net/port.php?port=25 )"
	],
	'53' => [
		"DNS",
		"DNS is a required process for network connectivity. That said, good practice is to have an internal DNS server and require all workstations to use that instead of an ISP or public (eg Google) server. This prevents DNS poisoning attacks and having your workstations forced to visit malicious servers by mistake.\n( more http://www.speedguide.net/port.php?port=53 )",
		"DNS is a required process for network connectivity. That said, good practice is to have an internal DNS server and require all workstations to use that instead of an ISP or public (eg Google) server. By allowing DNS requests to leave your network you are at risk of allowing an attacker to control DNS resolution and subsequently forcing internal workstations to visit servers hosting more malicious content. Only your internal DNS server should be allowed to successfully connect on outbound port 53.\n( more http://www.speedguide.net/port.php?port=53 )"
	],
	'123' => [
		"NTP",
		"This port is used to sync time with a remote time server.  It is best to have one internal time server with access to the outside, while all other network devices are forced to only use that for syncing time.  Having proper time syncing across a network helps with debugging network logs, but more importantly it is required some some types of authentication such as Windows domain logins.\n( more http://www.speedguide.net/port.php?port=123 )",
		"This port is used to sync time with a remote time server.  It is best to have one internal time server with access to the outside, while all other network devices are forced to only use that for syncing time.  Allowing outside NTP access to workstations can be combined with a DNS poisoning attack to force these devices to obtain the wrong time from a malicious external server. This leads to many issues with some authentication platforms such as Microsoft Active Directory based Windows domain logins. (basically a denial-of-service attack). This port should always be blocked with an exception created for only your internal time server to communicate with a known time server like NIST.\n( more http://www.speedguide.net/port.php?port=123 )"
	],
	'135' => [
		"RPC",
		"This port is used by Windows sub-systems for cross LAN operations.  Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=135 )",
		"This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=135 )"
	],
	'137' => [
		"NETBIOS",
		"This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=137 )",
		"This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=137 )"
	],	
	'138' => [
		"NETBIOS",
		"This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=138 )",
		"This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=138 )"
	],	
	'139' => [
		"NETBIOS",
		"This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=139 )",
		"This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=139 )"
	],
	'445' => [
		"AD/SMB",
		"This port is used by Windows sub-systems for cross LAN file operations such as file servers. Despite a legit need for the port, several worms have been known to exploit this port in order to propagate. By blocking this port, you are protecting yourself from several attack vectors commonly used by malicious code. (Blaster Worm, Reatle etc), as well as possibly leaking sensitive data across the public internet.\n( more http://www.speedguide.net/port.php?port=445 )",
		"This port is used by Windows sub-systems for cross LAN operations.  Traffic on this port can leak sensitive information to external targets, invite propagation of common Blaster-type worms, and possibly your ISP threatening to shut you down.  Since the port is used for mostly LAN-type operations, this port should be filtered from exiting your network.\n( more http://www.speedguide.net/port.php?port=445 )"
	],
	'6665' => [
		"IRC-5",
		"Most common malware will exfiltrate data from your network by some means. IRC is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server. IRC is also commonly used to Command & Control many exploited machines known as a bot-net.  Blocking this port also helps prevent an attacker from roaming free within your network.\n( more http://www.speedguide.net/port.php?port=6665 )",
		"Most malware will exfiltrate data from your network by some means. One of the most common means is via an IRC connection to an external server.  Allowing IRC traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)  You are also at risk from having workstations harvested as part of a bot-net in which IRC serves as command and control.  This port needs to be blocked in order to mitigate most of these common threat-types.\n( more http://www.speedguide.net/port.php?port=6665 )"
	],
	'6667' => [
		"IRC-7",
		"Most common malware will exfiltrate data from your network by some means. IRC is one of the simplest form and is currently used by hundreds of known threats.  Blocking outbound FTP connections prevents the low-hanging-fruit malware from sending your sensitive data to an external server. IRC is also commonly used to Command & Control many exploited machines known as a bot-net.  Blocking this port also helps prevent an attacker from roaming free within your network.\n( more http://www.speedguide.net/port.php?port=6667 )",
		"Most malware will exfiltrate data from your network by some means. One of the most common means is via an IRC connection to an external server.  Allowing IRC traffic to leave your network means an attacker has an easy, highly usable means to leak your company data to an external server.  This port should always be blocked, with exceptions created for users that actually require access. (exception should allow only that user to only the external server they need.)  You are also at risk from having workstations harvested as part of a bot-net in which IRC serves as command and control.  This port needs to be blocked in order to mitigate most of these common threat-types.\n( more http://www.speedguide.net/port.php?port=6667 )"
	]
);

$red="\e[31m";
$green="\e[32m";
$white="\e[0m";
$yellow="\e[0;93m";
$redbg="\e[41m";
$greenbg="\e[42m";


print "\n\n\nRiS-Egress-Test Tool v1.0";
print "\nCopyright (C) 2015 RawInfoSec.com          \@RawInfoSec";
print "\n\nCurrently using: ".$host."\n";

foreach $port ( keys %portdefs )  {
	print $white."\n\n\n\nTesting ".$portdefs{$port}[0]." Port ".$port.".......";
	$ret=testport($port,$host);
	if ($ret) {
		# oh noes, port is accessible :(
		print $yellow.$redbg." ".$portdefs{$port}[0]." is OPEN! ".$white."\n\n";
		print $portdefs{$port}[2];
	} else {
		# yay, port is blocked!!! :)
		print $greenbg." ".$portdefs{$port}[0]." is BLOCKED! ".$white."\n\n";
		print $portdefs{$port}[1];
	}
}


print "\n\n\n";
