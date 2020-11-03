## Updating ed25519

ed25519 is a vendored copy of git@github.com:pyca/ed25519.git.

Here's one way to update the vendored copy:
```bash
cd securesystemslib/_vendor
rm -rf ed25519/
git clone git@github.com:pyca/ed25519.git
touch ed25519/__init.py # needed by python<3.3
git clean -f ed25519/
git commit -a
```

Note that this does not commit any new files: Our copy does not include
all of the upstream files.

Remember to update the expected upstream hash in test-ed25519-upstream.sh.

