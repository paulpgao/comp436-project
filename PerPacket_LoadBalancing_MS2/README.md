## Description

This folder is specifically for Per-Packet load balancing in Milestone
2 Tasks 2-3.

The perpacket.p4 switch program is very similar to ECMP_LoadBalancing_MS1.
The only difference is that in line 160, the hash value is selected to
be directly alternating (takes % 2), so that no two consecutive packets will
go through the same path.

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
