## Description

This folder is specifically for Flowlet Switching load balancing in Milestone
3 Tasks 1-2.

The flowletswitching.p4 switch program is very similar to the previous two
Milestone programs. However, the difference here between regular ECMP
load balancing is that we account for latencies between same flows. I created
two additional registers of length 100 (for the 100 flows) that represent
the timestamps and flowlet IDs for each distinct flow. In set_ecmp_select(), 
I first hashed the flow to determine a specific flow index to access these
registers with. Then, I checked the current timestamp with the previous
timestamp register's recorded timestamp. If there was sufficient latency in
this one flow, then I would increment the flowlet ID. Lastly, I rehashed to 
determine the path to take, with both the original 5-tuple and the additional 
flowlet ID, and updated the registers with a new timestamp and flowlet ID. 

## Run Instructions

1. In your shell, run:
   ```bash
   make run
   ```
   This will:
   * Compile the p4 program
   * Start a Mininet instance with four switches
   * The sender host is assigned IP `10.0.0.1`
   * The receiver host is assigned IP `10.0.2.2`.

2. You should now see a Mininet command prompt. Open two terminals
for `h1` and `h2`, respectively:
   ```bash
   mininet> xterm h1 h2
   ```
3. Each host includes a small Python-based messaging client and
server. In `h2`'s xterm, start the server:
   ```bash
   ./receive.py
   ```
4. In `h1`'s xterm, send a message to `h2`:
   ```bash
   ./send.py "P4 is cool"
   ```
   The message will be displayed for the very last packet (query).
5. Type `exit` to leave each xterm and the Mininet command line.
   Then, to stop mininet:
   ```bash
   make stop
   ```
   And to delete all pcaps, build files, and logs:
   ```bash
   make clean
   ```
