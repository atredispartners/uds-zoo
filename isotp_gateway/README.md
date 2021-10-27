# ISO-TP to HTTP Gateway

## Install
Python dependency management is done using `pipenv`.

**Install Pipenv**
```
$ sudo pip3 install pipenv
```

**Install Dependencies**
```
$ pipenv install
```

## Startup
You need to have the ISO-TP kernel module installed. This may already be in your kernel, or install from https://github.com/hartkopp/can-isotp.

**Load Module**
```
$ sudo modprobe can
```

**Create Interface**
```
$ sudo ip link add dev vcan0 type vcan
$ sudo ip link set up vcan0
```

```
$ pipenv shell
$ python gateway.py start
```

## Doing Stuff
Assuming you have the gateway running along with the UDS controller and exercises.
```
$ python gateway.py start               
starting thread for id: 0x01 level: Level1 rxid: 0x01 txid: 0x90
starting thread for id: 0x02 level: Level2 rxid: 0x02 txid: 0x90
starting thread for id: 0x03 level: Level3 rxid: 0x03 txid: 0x90
starting thread for id: 0x04 level: Level4 rxid: 0x04 txid: 0x90
starting thread for id: 0x05 level: Level5 rxid: 0x05 txid: 0x90
```

**Recv Data**
```
$ isotprecv -s 0x01 -d 0x90 vcan0
```

**Send Data**
```
$ echo 22 13 37 | isotpsend -s 0x01 -d 0x90 vcan0
```


