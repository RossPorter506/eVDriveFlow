#!/bin/bash

cd secc
python evse_gui.py &
cd ../evcc
python start_ev.py
