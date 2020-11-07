## Description

This folder is specifically for ECMP load balancing in Milestone 1
Tasks 1-3 and Milestone 2 Task 1.

This program utilizes two tables (similar to exercises/load_balance) to
forward packets to the destination host. The first table, ecmp_group,
uses a hash function on a 5-tuple to randomly choose a path where the
packet will be sent to after Switch 1. This will be the hash value
used in the second table.

The second table, ecmp_nhop, uses the hash result to forward the 
packet with the respective egress port to the next switch, either 2 or
3. Note that only Switch 1 utilizes the ecmp_group action table. 
However, all switches utilize the ecmp_nhop action table. Regular 
forwarding is performed in ecmp_nhop for the other 3 switches 
(S2, S3, S4), where a singular hash value is specified
(only one path out of the switch).

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
