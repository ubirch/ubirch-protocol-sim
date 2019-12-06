from network import LTE
from machine import UART
import sys
import binascii
import time
import _thread

lte = LTE()
lte.init()

uart = UART(1, baudrate=921600, pins=('P5', 'P98', 'P7', 'P99'), timeout_chars=1)

def read_rsp(size=None, timeout=-1):
    time.sleep(.25)
    if timeout < 0:
        timeout = 20000
    elif timeout is None:
        timeout = 0
    
    while not uart.any() and timeout > 0:
        time.sleep_ms(1)
        timeout -= 1

    if size is not None:
        rsp = uart.read(size)
    else:
        rsp = uart.read()
    if rsp is not None:
        return rsp
    else:
        return b''

def reader():
    while True:
        b = read_rsp()
        if b != b'':
            sys.stdout.write(b)
        time.sleep_ms(1)

_thread.start_new_thread(reader, ())

while True:
    line = sys.stdin.readline().strip()
    uart.write(line+"\r\n") 