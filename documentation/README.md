# Orcano

## Overview

Orcano implements what is in effect a fancy reverse polish notation calculator. Code consists of a space-separated list of commands. In addition to offering stateless calculation, the service provides permanent storage of numbers through set/get commands. User accounts are identified by a 64-bit "username" and are authenticated through a fixed 64-bit passsword.

The service is implemented as a GameCube executable running inside the Dolphin emulator. A Python frontend implements all the necessary host functionality including networking, session management and disk access. It also enforces the OTP authentication method. The frontend communicates with the GameCube-side (hereafter "backend") via a USB Gecko peripheral configured into the emulator which is essentially just a serial port exposed as a local TCP socket.

Requests are queued in the frontend and then passed serially to a worker process running the backend in Dolphin. The emulator was patched to facilitate this usage: 
* A DMA mode of operation was added to the serial port to improve performance
* CPU usage and latency of the serial port driver was dramatically decreased through improved blocking behavior
* Port assignment was made configurable via command line to allow multiple instances of the emulator to run at the same time

The frontend and backend communicate via a simple message protocol consisting of a message type, size, and data blob. Requests are subject to strict 250ms timeouts. If the emulator does not complete the request within 250ms or responds in an invalid way, the emulator is killed and restarted.

## Directory structure
* `service` - frontend and final redistributable deployed on vulnboxes
* `image` - GameCube backend
* `dolphin` - patches and Dockerfile for the emulator
* `checker` - checker

## Flags

Flags are stored as numbers under random users. Flags are split into three-character groups, ASCII-encoded and converted to big-endian integers. These are then stored in ascending order from offset zero in the flag account. The usernames for these accounts are provided to players via attack info.

## Vulnerabilities

### Bad `boundsCheck`
The `boundsCheck` function implements a bounds check prior to execution of each command. It checks that there is a sufficient number of elements on the stack for the relevant command to execute to prevent underflows, and also checks that the stack is not completely full to prevent overflows. However, the code responsible for overflow prevention mistakenly checks the wrong variable against the upper bound to guard against overflow. As a result, the stack can be overflowed by pushing enough elements.

This can be exploited in the classical way: by pushing enough elements, eventually we reach the return address stored on the stack. We can then overwrite this with the address of our data on the stack, where we can place some PowerPC shellcode. This shellcode can, for example, call the helpful functions `hostGetNumber` and `hostPrintNumber` followed by `hostComplete` to dump the keys for the flag account. The flag can then be retrieved normally.

This can be patched by e.g. changing the instruction at 0x80004ff8 from `cmpwi cr7, r4, 0xff` to `cmpwi cr7, r3, 0xff`, thereby checking the correct variable and preventing stack overflows.
