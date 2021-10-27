## Level 7

ReadMemoryByAddress (0x23)

This level is the same as level 6, however the ReadMemoryByAddress call has been modified to ensure you cannot request
sensitive values from memory ranges 0x60-0x78 (Seed/Xor Key)

```go
    //check to make sure request cannot access the seed + key
if (addr >= CURRENT_SEED && addr <= (XOR_KEY+SEED_LEN)) || (addr < CURRENT_SEED && (addr+mSize) > CURRENT_SEED){
//return security access denied
return []byte{uds.NR, uds.ReadMemoryByAddress, uds.SAD}
}
```

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
<Level changed> 0x07: Level7
# SecurityAccess - request seed
TX: 27 01
# SecurityAccess - Positive Response
RX: 67 01e7dba1c95d760512

# ReadMemoryByAddress 00-ff - confirmation ranges are now protected
TX: 23 11 00 ff
# Negative Response - Security Access Denied
RX: 7f 2333

# ReadMemoryByAddress 60-90 - confirmation ranges are now protected
TX: 23 11 60 30
# Negative Response - Security Access Denied
RX: 7f 2333

# ReadMemoryByAddress 00-60 - confirmation ranges are now protected
TX: 23 11 00 60
# Positive Response
RX: 63 000000000000000000000000000000000100000000000000000000000000000041545245444953313333370000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000

# ReadMemoryByAddress 00-61 - confirmation ranges are now protected
TX: 23 11 00 61
# Negative Response - Security Access Denied
RX: 7f 2333

#R eadMemoryByAddress 0x100000001-0xff
TX: 23 15 01 00 00 00 01 fe
# Positive Response
RX: 63 0000000000000000000000000000000100000000000000000000000000000041545245444953313333370000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000e7dba1c95d76051200000000000000006a50660d26dc3289000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```