# uds-zoo

The architecture of the framework is split between the following items:

- Controller - handles request routing, node registration, client interface
- Nodes - these are the individual UDS services/levels

The easiest way to use the project is to use the provided Docker file, otherwise instructions for running the project
outside docker are found below.

### Docker

Build the image

```shell
docker build -t udszoo .
```

Run it

```shell
docker run -d -p 8888:8888 udszoo
```

The application will now be available at `http://localhost:8888/`

### Manual Start Up Procedures

If you would rather run the project outside of docker, the controller needs to be started before the nodes:

```
$ cd cmd/controller
$ go build
$ ./controller
```

The nodes must each be started on their own, all the provided nodes (found in ./examples) are configured to register
with the controller. If you wish to disable the registration process during node development, uncomment or add the node
setting `node.DONTREGISTERINSTANCE = true` to the `main()` function. The following example shows building and starting
the `level1` node:

```
$ cd examples/level1
$ go build
$ ./level1
```

You can test that the node has been registered by requesting the `/instances` path on the controller:

```
curl http://localhost:8888/instances | jq . 
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   347  100   347    0     0   338k      0 --:--:-- --:--:-- --:--:--  338k
[
  {
    "id": "0x01",
    "name": "Getting your first flag.",
    "description": "Getting your first flag.",
    "addr": "unix:/home/tom/source/uds-zoo/src/uds/examples/level1/Level1.uds.sock"
  }
]
```

To test that the controller is routing correctly to node it can be accessed through the `/uds/{id}` path as seen in the
following example request:

```
$ curl http://localhost:8888/uds/0x01 -X POST -H 'Content-Type: application/json' -d '{"sid": "22", "data": "1337"}'
{"sid":"62","data":"61626279736669727374666c6167"}
```

### Single Node Execution

When developing or debugging a node it can be easier to execute the node directly without involving the controller. This
can be done by setting the value `node.DONTREGISTERINSTANCE = true` within `main()` and executing the node directly. The
following example shows this process with the provided node example `poc`:

```
$ cd examples/poc/
$ go run main.go
```

Within the directory you started the node a unix socket will be created that allows you to access the node Calling POC
service. From the same directory:

```
$ curl --unix-socket ./sillypoc.uds.sock http://localhost/uds -X POST -d '{"sid": "10", "payload": "4141"}'
{"sid":"10","data":"4242"}
```

### Docs

Use `godoc` to view documentation on packages

```
$ godoc
```

Browse to: http://localhost:6060/pkg/github.com/atredispartners/uds-zoo/uds/node/
