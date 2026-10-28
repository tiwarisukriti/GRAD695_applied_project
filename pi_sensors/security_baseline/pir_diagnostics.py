#!/usr/bin/env python3
"""
Diagnostic: prints the raw PIR pin state every 0.5s so you can see if
the signal is changing at all when you wave your hand in front of it.

Wait at least 60 seconds after power-up before testing - PIR sensors
need time to calibrate to ambient IR.
"""

import time
from gpiozero import DigitalInputDevice

PIR_PIN = 18  # GPIO18 (physical pin 12)

sensor = DigitalInputDevice(PIR_PIN)

print("Warming up for 60s (PIR sensors need this to calibrate)...")
for i in range(60, 0, -1):
    print(f"  {i}s remaining", end="\r")
    time.sleep(1)
print("\nWarm-up done. Wave your hand in front of the sensor.\n")
print("Watching raw pin state. Press Ctrl+C to stop.\n")

try:
    last_state = None
    while True:
        state = sensor.value
        if state != last_state:
            print(f"{time.strftime('%H:%M:%S')}  Pin state changed to {state}  (1=motion, 0=idle)")
            last_state = state
        time.sleep(0.1)
except KeyboardInterrupt:
    print("\nStopped.")