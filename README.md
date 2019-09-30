You don't need to use regex to parse those windows firewall logs. You can use parse anchor instead. The trick is that since there are no labels in the log you need to start from the beginning of the log line. 

According to the [Microsoft Technet]: https://technet.microsoft.com/en-us/library/cc758040%28v=ws.10%29.aspx documentation the header of the log file contains:

Version — Displays which version of the Windows Firewall security log is installed.
Software — Displays the name of the software creating the log.
Time — Indicates that all the timestamp information in the log are in local time.
Fields — Displays a list of fields that are available for security log entries, if data is available.

While the body of the log file contains:

date — The date field identifies the date in the format YYYY-MM-DD.
time — The local time is displayed in the log file using the format HH:MM:SS. The hours are referenced in 24-hour format.
action — As the firewall processes traffic, certain actions are recorded. The logged actions are DROP for dropping a connection, OPEN for opening a connection, CLOSE for closing a connection, OPEN-INBOUND for an inbound session opened to the local computer, and INFO-EVENTS-LOST for events processed by the Windows Firewall, but were not recorded in the security log.
protocol — The protocol used such as TCP, UDP, or ICMP.
src-ip — Displays the source IP address (the IP address of the computer attempting to establish communication).
dst-ip — Displays the destination IP address of a connection attempt.
src-port — The port number on the sending computer from which the connection was attempted.
dst-port — The port to which the sending computer was trying to make a connection.
size — Displays the packet size in bytes.
tcpflags — Information about TCP control flags in TCP headers.
tcpsyn — Displays the TCP sequence number in the packet.
tcpack — Displays the TCP acknowledgement number in the packet.
tcpwin — Displays the TCP window size, in bytes, in the packet.
icmptype — Information about the ICMP messages.
icmpcode — Information about the ICMP messages.
info — Displays an entry that depends on the type of action that occurred.
path — Displays the direction of the communication. The options available are SEND, RECEIVE, FORWARD, and UNKNOWN.

To parse the statistical data from the logs use the following:
`parse "* * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port`

To parse the full log, use the following:
`parse "* * * * * * * * * * * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port, Size, TCP_Flags, TCP_SYN, TCP_ACK, TCP_Win, ICMP_Type, ICMP_Code, Info, Path`

To count/group by destination ports:
`_sourceCategory="uploads/windows/firewall"
| parse "* * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port
| where Destination_Port <> "-"
| num(Destination_Port)
| count by Destination_Port, Protocol
| sort by _count`

To count/group by source ports:
`_sourceCategory="uploads/windows/firewall"
| parse "* * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port
| where Source_Port <> "-"
| number(Source_Port)
| where Source_Port <=49151 //Registered ports
| count by Source_Port, Protocol
| sort by _count`

A lookup file can be added to categorize the service:
`| parse "* * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port
| where Destination_Port <> "-"
| lookup Service, Description from https://raw.githubusercontent.com/r00tgate/sumo-logic-windows-firewall/master/ports_services.csv on Destination_Port=Port
| num(Destination_Port)
| count by Destination_Port, Protocol, Service, Description
| sort by _count`

`_sourceCategory="uploads/windows/firewall"
| parse "* * * * * * * * " as Date, Time, Action, Protocol, Source_IP, Destination_IP, Source_Port, Destination_Port
| where Source_Port <> "-"
| lookup Service, Description from https://raw.githubusercontent.com/r00tgate/sumo-logic-windows-firewall/master/ports_services.csv on Destination_Port=Port
| number(Source_Port)
| where Source_Port <=49151 //Registered ports
| count by Source_Port, Protocol, Service, Description
| sort by _count`
