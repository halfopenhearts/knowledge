chicken butt

linux auditing and logging

syslog and systemd-journald

/etc/rsyslog.conf
/etc/rsyslog.d/



Syslog Message Facilities RFC 5424

Numerical Code	Facility
0	kernel messages
1	user-level messages
2	mail system
3	system daemons
4	security/authorization messages
5	messages made by syslogd
6	line printer subsystem
7	network news subsystem



Syslog Message Severities RFC 5424

Numerical Code	Severity
0	Emergency
1	Alert
2	Critical
3	Error
4	Warning
5	Notice
6	Informational
7	Debug



RFC 5424                  The Syslog Protocol                 March 2009


   character, %d62).  The number contained within these angle brackets
   is known as the Priority value (PRIVAL) and represents both the
   Facility and Severity.  The Priority value consists of one, two, or
   three decimal integers (ABNF DIGITS) using values of %d48 (for "0")
   through %d57 (for "9").

   Facility and Severity values are not normative but often used.  They
   are described in the following tables for purely informational
   purposes.  Facility values MUST be in the range of 0 to 23 inclusive.

          Numerical             Facility
             Code

              0             kernel messages
              1             user-level messages
              2             mail system
              3             system daemons
              4             security/authorization messages
              5             messages generated internally by syslogd
              6             line printer subsystem
              7             network news subsystem
              8             UUCP subsystem
              9             clock daemon
             10             security/authorization messages
             11             FTP daemon
             12             NTP subsystem
             13             log audit
             14             log alert
             15             clock daemon (note 2)
             16             local use 0  (local0)
             17             local use 1  (local1)
             18             local use 2  (local2)
             19             local use 3  (local3)
             20             local use 4  (local4)
             21             local use 5  (local5)
             22             local use 6  (local6)
             23             local use 7  (local7)

              Table 1.  Syslog Message Facilities

   Each message Priority also has a decimal Severity level indicator.
   These are described in the following table along with their numerical
   values.  Severity values MUST be in the range of 0 to 7 inclusive.





will show what kind of system youre on, like systemd which journeld is only used on
  ps -p 1 -o comm=



have to use this for xml viewing
xpath -q -e '//element/@attribute' file.xml
xpath -q -e '//address/@addr | //port/@portid' output.xml | md5sum


garviel@terra:~$ jq -s 'map(."id.orig_h") | unique | length' /home/garviel/conn.log
31
Use jq to locate and count the unique originating endpoint IP addresses in the file. Enter the number of unique originating IP addresses as the flag.






jq -s '[.[] | select(.resp_bytes != null and (.resp_bytes | tonumber) > 40)] | length' conn.json

Use jq to locate and count connections where the destination IP sent more than 40 bytes to the source IP.

Flag format: #


