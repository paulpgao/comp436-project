#!/bin/bash
python send.py put 0 1
python send.py put 1 2
python send.py put 2 3
python send.py put 3 4

python send.py get 0
python send.py get 1
python send.py get 2
python send.py get 3

python send.py put 1025 1026
python send.py put 9000 0
python send.py put 4 0

python send.py get 1025
python send.py get 4
python send.py get 5

