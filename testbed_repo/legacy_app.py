# testbed_repo/legacy_app.py
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, ec

# 1. Hardcoded deprecated hashing primitives
legacy_md5 = hashlib.md5(b"audit_session_token_1092").hexdigest()
legacy_sha1 = hashlib.sha1(b"transaction_block_entry").hexdigest()

# 2. Hardcoded quantum-vulnerable asymmetric keys
rsa_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048  # Vulnerable RSA
)

ecc_private_key = ec.generate_private_key(
    ec.SECP256R1()  # Vulnerable ECC
)