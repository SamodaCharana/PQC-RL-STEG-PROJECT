# src/pqc/cli.py
"""
Simple CLI to exercise pqc_module functions.

Usage examples:
    python -m src.pqc.cli --demo
    python -m src.pqc.cli --sign "message"
"""

import argparse
from src.pqc.pqc_module import (
    kyber_generate, kyber_encapsulate, kyber_decapsulate,
    dilithium_generate, dilithium_sign, dilithium_verify, roundtrip_demo
)

def main():
    parser = argparse.ArgumentParser(description="PQC module CLI (Kyber + Dilithium)")
    parser.add_argument("--demo", action="store_true", help="Run full roundtrip demo")
    parser.add_argument("--gen-kyber", action="store_true", help="Generate Kyber keys and print lengths")
    parser.add_argument("--encap", action="store_true", help="Encapsulate with generated Kyber keys (demo)")
    parser.add_argument("--gen-dilithium", action="store_true", help="Generate Dilithium keys and print lengths")
    parser.add_argument("--sign", type=str, help="Sign a message with generated Dilithium key (demo)")
    args = parser.parse_args()

    if args.demo:
        res = roundtrip_demo(b"CLI demo message")
        print("Roundtrip demo result:")
        for k, v in res.items():
            print(f"  {k}: {v}")
        return

    if args.gen_kyber:
        pk, sk = kyber_generate()
        print("Kyber pk len:", len(pk))
        print("Kyber sk len:", len(sk))
    if args.encap:
        pk, sk = kyber_generate()
        ct, ss = kyber_encapsulate(pk)
        ss2 = kyber_decapsulate(ct, sk)
        print("Ciphertext len:", len(ct))
        print("Shared secret match:", ss == ss2)
    if args.gen_dilithium:
        pk, sk = dilithium_generate()
        print("Dilithium pk len:", len(pk))
        print("Dilithium sk len:", len(sk))
    if args.sign:
        pk, sk = dilithium_generate()
        message = args.sign.encode()
        signature = dilithium_sign(message, sk)
        ok = dilithium_verify(message, signature, pk)
        print("Signature len:", len(signature))
        print("Signature verified:", ok)

if __name__ == "__main__":
    main()
