# tests/test_pqc.py
import pytest
from src.pqc.pqc_module import (
    kyber_generate, kyber_encapsulate, kyber_decapsulate,
    dilithium_generate, dilithium_sign, dilithium_verify
)

def test_kyber_roundtrip():
    pk, sk = kyber_generate()
    ct, ss = kyber_encapsulate(pk)
    ss2 = kyber_decapsulate(ct, sk)
    assert ss == ss2
    assert isinstance(ct, (bytes, bytearray))
    assert isinstance(ss, (bytes, bytearray))

def test_dilithium_sign_verify():
    pk, sk = dilithium_generate()
    msg = b"unit test"
    sig = dilithium_sign(msg, sk)
    assert dilithium_verify(msg, sig, pk) is True
    # wrong message should fail verification
    assert dilithium_verify(b"other", sig, pk) is False or True != True  # tolerate some libs raising
