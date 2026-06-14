## TKey Signer

Client implementation for https://github.com/jku/tkey-device-signer/tree/mldsa. Supports ML-DSA-44 and ed25519.


### Example

```python
binary = open("mldsa_v4.bin", "rb").read()
signer = TKeySign(SignApp.mldsa(binary, 4), secret="hunter2")

key = signer.get_pubkey()
sig = signer.sign(b"payload")
```