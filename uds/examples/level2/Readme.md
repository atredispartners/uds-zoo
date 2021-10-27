## Level 2 - Diagnostic Session Required
This level requires the user to switch from the default session to session 0x02 before access to the flag is allowed.

```shell
#ReadDataByIdentifier - flag - Negative Response - Service not supported in current session
TX: 22 1337
RX: 7f 227f

#DiagnosticSession - Start 0x02 - Positive Response
TX: 10 02
RX: 50 02

#ReadDataByIdentifier - flag - Positive Response
TX: 22 1337
RX: 62 643161676e3073316e672d793075722d7365737331306e
```