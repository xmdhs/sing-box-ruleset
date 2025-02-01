#!/bin/bash

set -e -o pipefail

wget https://github.com/SagerNet/sing-box/releases/download/v1.11.0/sing-box-1.11.0-linux-amd64.tar.gz
tar -zxvf sing-box-1.11.0-linux-amd64.tar.gz

curl -fsSL https://adguardteam.github.io/AdGuardSDNSFilter/Filters/filter.txt -o filter.txt

sing-box-1.11.0-linux-amd64/sing-box rule-set convert --type adguard --output output/AdGuardSDNSFilterSingBox.srs filter.txt
