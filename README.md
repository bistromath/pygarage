# Python garage door utility

This is a super simple TCP server intended for use as a garage door opener. See garagedoor-dongle.git for an example transmitter. It's made for use with the Pimoroni Automation HAT for Raspberry Pi.

It's nominally encrypted with a modern cipher, but I wouldn't trust it for anything serious. The service is not intended to be bulletproof and has not been tested extensively. As such, please don't expose it to the Internet.

Please edit garage.py and add a key -- it should be a good, random binary string of 24 bytes.
