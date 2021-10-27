## Level 0x9

DynamicallyDefineDataIdentifier (0x2c)

DynamicallyDefineDataIdentifier allows the client to dynamically define a new DataIdentifier by DataIdentifier or
MemoryAddress. This service provides a client the ability to create adhoc DataIdentifiers that can return multiple
DataRecords with one request.

Example DynamicallyDefineDataIdentifier - DefineByIdentifier (0x01)  Message:

`2c 01 f200 f190 01 00`

Message Definition:

```
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x01 - Define by DataIdentifier
dynamicallyDefinedDataIdentifier - 0xf200 - The new data identifier
sourceDataIdentifier - 0xf190 - The source data identifier (in this case, VIN)
positionInSourceDataRecord - 0x01 - The starting byte
memorySize - 0x00 - The offset in addition to the positionInSourceDataRecord
```

Positive Response:

```
6c 02f200
AddressAndLengthFormat - 0x02 - the requested sub-function value
dynamicallyDefinedDataIdentifier - 0xf200 - The new data identifier
```

This value can then be accessed using ReadDataByIdentifier (0x22):

```
# New identifier
TX: 22 f200
RX: 62 f1904154524544495331333337
# Source identifier
TX: 22 f190
RX: 62 f1904154524544495331333337
```

Example DynamicallyDefineDataIdentifier - DefineByAddress (0x02)  Message:

`2c 02 f300 11 20 10`

Message Definition:

```
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x02 - Define by Address
dynamicallyDefinedDataIdentifier - 0xf300 - The new data identifier
addressAndLengthFormat - 0x11 - high nibble is length of memory size, low is length of Address 
MemoryAddress - 0x20 - memory address to read from
MemorySize - 0x10 - size of the memory to read
```

Full example:

```
# DynamicallyDefineDataIdentifier - DefineByAddress
TX: 2c 02 f300 11 20 10
RX: 6c 02f300
# ReadDataByIdentifier 
TX: 22 f300
RX: 62 41545245444953313333370000000000
# ReadMemoryBy Address 
TX: 23 11 20 10
RX: 63 41545245444953313333370000000000
```

Example DynamicallyDefineDataIdentifier - clearDynamicallyDefinedDataIdentifier (0x03)  Message:

`2c 03 f300`

Message Definition:

```
DynamicallyDefineDataIdentifier - 0x2c
Sub-Function - 0x03 - clearDynamicallyDefinedDataIdentifier
dynamicallyDefinedDataIdentifier - 0xf300 - The data identifier to remove
```

Full example:

```
# DynamicallyDefineDataIdentifier - DefineByAddress
TX: 2c 02 f300 11 20 10
RX: 6c 02f300
# ReadDataByIdentifier 
TX: 22 f300
RX: 62 41545245444953313333370000000000
# Clear DynamicallyDefinedDataIdentifier
TX: 2c 03 f300
RX: 6c 03f300
# DataIdentifier no longer available
TX: 22 f300
RX: 7f 2231
```

Dynamically created identifiers can also be built up using multiple records or requests

```
# DynamicallyDefineDataIdentifier - DefineByAddress with multiple addresses/lengths [20,10] [00,10] [20,10]
TX: 2c 02 f300 11 20 10 00 10 20 10
RX: 6c 02f300
TX: 22 f300
RX: 62 415452454449533133333700000000000000000000000000000000000000000041545245444953313333370000000000
# DynamicallyDefineDataIdentifier - DefineByIdentifier - adding the identifier 0xf190 to our previous identifier
TX: 2c 01 f300 f190 01 00
RX: 6c 02f300
# ReadDataByIdentifier - full value 
TX: 22 f300
RX: 62 415452454449533133333700000000000000000000000000000000000000000041545245444953313333370000000000f1904154524544495331333337
```