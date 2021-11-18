#!/bin/bash

set -x

systemctl stop octorpki
systemctl disable octorpki

deluser octorpki
delgroup octorpki

exit 0
