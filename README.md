# WiFiTrafficForwardingClientandServer
## Client / ClientMACFilter
C client that sniffs traffic on a wireless monitor interface and sends the traffic to the server. Also receives traffic from the server and broadcasts it on the monitor interface.
## ServerConsole
C# server that allows multiple clients to connect to it and sends traffic from a client to each other connected client.



TODO: switch per-thread queue to single queue  
TODO: add clients that do not use compression  
TODO: build compression dictionaries and check ratios + cpu usage  