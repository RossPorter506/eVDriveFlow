#!/bin/bash

# Start a session between unsupporting SECC and a supporting EVCC
cd ../eVDriveFlow/secc
python evse_gui.py &
cd ../../eVDriveFlowCustom/evcc
python start_ev.py
