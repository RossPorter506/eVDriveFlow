#!/bin/bash

cd malicious_secc
python evse_gui.py &
cd ../evcc
python start_ev.py
