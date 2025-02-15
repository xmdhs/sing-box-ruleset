# https://github.com/SagerNet/sing-geosite/blob/main/.github/release-rule-set.sh

#!/bin/bash

set -e -o pipefail


wget https://github.com/SagerNet/sing-box/releases/download/v1.11.0/sing-box-1.11.0-linux-amd64.tar.gz
tar -zxvf sing-box-1.11.0-linux-amd64.tar.gz

for file in output/*.json; do
    sing-box-1.11.0-linux-amd64/sing-box rule-set compile "$file"
done


cd output
git init
git config --local user.email "github-action@users.noreply.github.com"
git config --local user.name "GitHub Action"
git remote add origin https://github-action:$GITHUB_TOKEN@github.com/xmdhs/sing-box-ruleset.git
git branch -M rule-set
git add .
git commit -m "Update rule-set"
git push -f origin rule-set