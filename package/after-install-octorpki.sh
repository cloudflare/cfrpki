#!/bin/bash

set -x

addgroup --system octorpki
adduser --system --home /var/lib/octorpki --shell /usr/sbin/nologin --disabled-login --group octorpki

systemctl daemon-reload
systemctl enable octorpki.service
systemctl start octorpki

exit 0
