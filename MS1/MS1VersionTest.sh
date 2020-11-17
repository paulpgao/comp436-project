#!/bin/bash

# Add some more versions
python send.py put 0 5 # v1
python send.py put 0 10 # v2
python send.py put 0 15 # v3
python send.py put 0 20 # v4
python send.py put 0 25 # v5
python send.py put 0 30 # v6(illegal)

python send.py get 0 0
python send.py get 0 1
python send.py get 0 2
python send.py get 0 3
python send.py get 0 4
python send.py get 0 5
python send.py get 0 6
python send.py get 0 5
python send.py get 0 4
python send.py get 0 3
python send.py get 0 2
python send.py get 0 1
python send.py get 0 0