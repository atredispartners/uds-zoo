## Level 0x8

WriteMemoryByAddress (0x3d)

This level is the same as level 7 - the following security rules have been implemented around sensitive memory:

Write Prohibited - 0x50 - 0x64

Read Prohibited - 0x53 - 0x64

```
	// ACCESS_LEVEL pack together to use less memory
	ACCESS_LEVEL  = 0x50
	SEED_SENT     = 0x51
	AUTH_ATTEMPTS = 0x52
	CURRENT_SEED  = 0x53
	XOR_KEY       = 0x5C
```

Example WriteMemoryByAddress Message:

`3d 11 00 01 ff`

Message Definition:

```
WriteMemoryByAddress - 0x3d 
AddressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address 
MemoryAddress - 0x00 - memory address to write to
MemorySize - 0x01 - size of memory write
DataRecord - 0xff

Positive Response:
7d 110001
AddressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address
MemoryAddress - 0x00 - memory address to written to
MemorySize - 0x01 - size of memory written
```

```shell
<Level changed> 0x08: Level8
```