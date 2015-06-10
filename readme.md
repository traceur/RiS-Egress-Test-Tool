# RiS-Egress-Test.pl

### 20150209 kevin@rawinfosec.com

## Client side tool to determine if the currently connected network is blocking a set of ports commonly used to exploit network devices from inside the firewall.

### This tool connects to egress.rawinfosec.com. You can change this in the source to a server of your choice. We have configured and made available this server
     for the time being but do not warranty availability in the future.

### This tool does not send any of your data to our server. It simply attempts to create the initial TCP connections.

### Ports tested are as per SANS Egress Filtering FAQ plus a couple RawInfoSec feel should be added.  We have not yet implemented UDP tests.
     SANS PDF - https://www.sans.org/reading-room/whitepapers/firewalls/egress-filtering-faq-1059?show=egress-filtering-faq-1059&cat=firewalls

### Copyright (C) 2015 RawInfoSec.com

### Author: Kevin Creechan     @RawInfoSec     kevin@rawinfosec.com
#### Version: 1.0 (20150125-1)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
#
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
#
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
