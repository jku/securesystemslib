#!/bin/bash

# Check for new commits in upstream ed25519
#
# Return 0 if the upstream ed25519 master branch HEAD matches the
# commit that our copy was vendored from.
#
# This is used in CI workflow to open an issue if new commits are found

set -eu

# This commit matches our securesystemslib/_vendor/ed25519/ content.
# If upstream changes, we should review the changes, vendor them,
# and update the hash here
pyca_ed25519_expected="c13748e1d24c5c00f6ce2b9c38a319ae02355d97"
pyca_ed25519_git_url="https://github.com/pyca/ed25519.git"

pyca_ed25519_master_head=$(git ls-remote "$pyca_ed25519_git_url" master | cut -f1)
if [ "$pyca_ed25519_master_head" != "$pyca_ed25519_expected" ]; then
    
    echo "Expected [master](https://github.com/pyca/ed25519/commits/master)" \
	 "to be commit ${pyca_ed25519_expected:0:7}, found" \
	 "${pyca_ed25519_master_head:0:7} instead" \
	 "([diff](https://github.com/pyca/ed25519/compare/${pyca_ed25519_expected}...master))."
    
    exit 1
fi

echo "No unexpected commits in https://github.com/pyca/ed25519.git"
