# src/pqc/pqc_module.py
"""
PQC module: Kyber (KEM) + Dilithium (signatures) wrapper.

This file tries to use 'pqcrypto' (PyPI) first. If pqcrypto is not installed
and liboqs-python (oqs) is installed and usable, it will attempt to use that.
If neither backend is found the module raises on import.

Provided functions:
- kyber_generate() -> (pk, sk)
- kyber_encapsulate(pk) -> (ciphertext, shared_secret)
- kyber_decapsulate(ciphertext, sk) -> shared_secret

- dilithium_generate() -> (pk, sk)
- dilithium_sign(message, sk) -> signature
- dilithium_verify(message, signature, pk) -> bool

- roundtrip_demo(message=b"...") -> dict (simple self-test)
"""

from typing import Tuple
import sys

_BACKEND = None

# Try pqcrypto implementation first (recommended)
try:
    from pqcrypto.kem.kyber512 import generate_keypair as _kyber_gen_kp, encrypt as _kyber_enc, decrypt as _kyber_dec
    from pqcrypto.sign.dilithium2 import generate_keypair as _dilithium_gen_kp, sign as _dilithium_sign, verify as _dilithium_verify
    _BACKEND = "pqcrypto"
except Exception:
    _BACKEND = None

# If pqcrypto unavailable, try liboqs (requires liboqs and liboqs-python built)
if _BACKEND is None:
    try:
        import oqs  # type: ignore
        _BACKEND = "liboqs"
    except Exception:
        _BACKEND = None

if _BACKEND is None:
    raise ImportError(
        "No PQC backend found. Install 'pqcrypto' (preferred) via pip:\n\n"
        "    pip install pqcrypto\n\n"
        "or build/install liboqs + liboqs-python and make 'oqs' importable.\n"
        "See https://open-quantum-safe.org for liboqs instructions."
    )

# --------------------------
# pqcrypto backend functions
# --------------------------
if _BACKEND == "pqcrypto":
    def kyber_generate() -> Tuple[bytes, bytes]:
        """
        Generate Kyber512 KEM keypair (public_key, secret_key) as bytes.
        """
        pk, sk = _kyber_gen_kp()
        return pk, sk

    def kyber_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate using recipient public key.
        Returns (ciphertext, shared_secret).
        """
        ct, ss = _kyber_enc(pk)
        return ct, ss

    def kyber_decapsulate(ciphertext: bytes, sk: bytes) -> bytes:
        """
        Decapsulate ciphertext using secret key to get shared secret.
        """
        ss = _kyber_dec(ciphertext, sk)
        return ss

    def dilithium_generate() -> Tuple[bytes, bytes]:
        """
        Generate Dilithium2 signing keypair (public_key, secret_key).
        """
        pk, sk = _dilithium_gen_kp()
        return pk, sk

    def dilithium_sign(message: bytes, sk: bytes) -> bytes:
        """
        Sign message using Dilithium secret key, returning signature bytes.
        """
        sig = _dilithium_sign(message, sk)
        return sig

    def dilithium_verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        """
        Verify signature with public key. Returns True if valid.
        pqcrypto.verify raises on failure; we convert to bool.
        """
        try:
            _dilithium_verify(message, signature, pk)
            return True
        except Exception:
            return False

# --------------------------
# liboqs backend functions
# --------------------------
else:
    # liboqs KeyEncapsulation and Signature APIs
    import oqs  # type: ignore

    # Kyber (KEM)
    def kyber_generate() -> Tuple[bytes, bytes]:
        """
        Generate Kyber KEM keypair (public_key, secret_key) using liboqs.
        Returns bytes (public_key, secret_key).
        """
        kem = oqs.KeyEncapsulation("Kyber512")
        # liboqs KeyEncapsulation.generate_keypair returns (public_key, secret_key)
        pk, sk = kem.generate_keypair()
        # ensure bytes
        return pk, sk

    def kyber_encapsulate(pk: bytes) -> Tuple[bytes, bytes]:
        """
        Encapsulate using recipient public key (liboqs).
        Returns (ciphertext, shared_secret).
        """
        kem = oqs.KeyEncapsulation("Kyber512")
        # encap_secret(public_key) -> (ciphertext, shared_secret)
        ct, ss = kem.encap_secret(pk)
        return ct, ss

    def kyber_decapsulate(ciphertext: bytes, sk: bytes) -> bytes:
        """
        Decapsulate ciphertext using secret key (liboqs).
        """
        kem = oqs.KeyEncapsulation("Kyber512")
        # decap_secret(ciphertext, secret_key) -> shared_secret
        ss = kem.decap_secret(ciphertext, sk)
        return ss

    # Dilithium (Signature)
    def dilithium_generate() -> Tuple[bytes, bytes]:
        """
        Generate Dilithium keypair (public_key, secret_key) using liboqs signature API.
        """
        sig = oqs.Signature("Dilithium2")
        pk, sk = sig.generate_keypair()
        return pk, sk

    def dilithium_sign(message: bytes, sk: bytes) -> bytes:
        """
        Sign a message using Dilithium secret key (liboqs).
        """
        sig = oqs.Signature("Dilithium2")
        signature = sig.sign(message, sk)
        return signature

    def dilithium_verify(message: bytes, signature: bytes, pk: bytes) -> bool:
        """
        Verify Dilithium signature using public key (liboqs). Returns True/False.
        """
        sig = oqs.Signature("Dilithium2")
        try:
            sig.verify(message, signature, pk)
            return True
        except Exception:
            return False

# --------------------------
# Utility demo
# --------------------------
def roundtrip_demo(message: bytes = b"hello pqc"):
    """
    Simple roundtrip demo:
    - generate kyber keys, encapsulate/decapsulate, check secret equality
    - generate dilithium keys, sign/verify message

    Returns a dict with all outputs.
    """
    result = {}
    # Kyber
    pk_k, sk_k = kyber_generate()
    ct, ss_enc = kyber_encapsulate(pk_k)
    ss_dec = kyber_decapsulate(ct, sk_k)
    result['kyber_pk_len'] = len(pk_k)
    result['kyber_sk_len'] = len(sk_k)
    result['ciphertext_len'] = len(ct)
    result['shared_secret_len'] = len(ss_enc)
    result['shared_secret_match'] = ss_enc == ss_dec

    # Dilithium
    pk_s, sk_s = dilithium_generate()
    sig = dilithium_sign(message, sk_s)
    verified = dilithium_verify(message, sig, pk_s)
    result['dilithium_pk_len'] = len(pk_s)
    result['dilithium_sk_len'] = len(sk_s)
    result['signature_len'] = len(sig)
    result['signature_valid'] = verified

    result['backend'] = _BACKEND
    return result


if __name__ == "__main__":
    print("PQC backend:", _BACKEND)
    print("Running quick roundtrip demo...")
    print(roundtrip_demo(b"test message"))
