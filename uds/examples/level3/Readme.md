## Level 3 - SecurityAccess Unlock
This level requires the user to unlock Security Access using seed 0x01 before the DiagnosticSession can be started and
the flag can be retrieved using ReadDataByIdentifier. The password for the SecurityAccess is hardcoded to `01020304`.

Example session
```shell
#ReadDataByIdentifier flag - Negative Response - Conditions Not Correct
TX: 22 1337
RX: 7f 2222

#DiagnosticSession 0x02 request - Negative Response - Security Access Denied Failure
TX: 10 02
RX: 7f 1033

#Security Access - Request Seed
TX: 27 01
RX: 67 014141414141

#Security Access Key - Negative Response - Invalid Key
TX: 27 0201010101
RX: 7f 2735

#Security Access Key - Positive Response
TX: 27 0201020304
RX: 67 02

#DiagnosticSession 0x02 request - Positive Response
TX: 10 02
RX: 50 02

#ReadDataByIdentifier flag - Positive Response
TX: 22 1337
RX: 62 6261626279736669727374756e6c6f636b
```