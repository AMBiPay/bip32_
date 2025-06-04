#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import hmac
import os
import time
import random
from dataclasses import dataclass
from typing import Tuple, Dict, Optional, Any, List

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string, sigdecode_string

class BIP32PAError(Exception):
    pass

@dataclass
class MasterKey:
    sk: SigningKey
    pk: VerifyingKey
    chaincode: bytes
    seed: bytes

@dataclass
class RevocationKey:
    pk: VerifyingKey
    chaincode: bytes

@dataclass
class Credential:
    cid: bytes
    pk: VerifyingKey
    server_id: str

class BIP32PARevoke:
    
    def __init__(self):
        self.curve = SECP256k1
        self.hash_func = hashlib.sha256
    
    def _h(self, *args) -> bytes:
        hasher = self.hash_func()
        for arg in args:
            if isinstance(arg, str):
                hasher.update(arg.encode('utf-8'))
            elif isinstance(arg, bytes):
                hasher.update(arg)
            elif isinstance(arg, VerifyingKey):
                hasher.update(arg.to_string())
            else:
                hasher.update(str(arg).encode('utf-8'))
        return hasher.digest()
    
    def _derive_key(self, sk: SigningKey, data: bytes) -> SigningKey:
        try:
            hmac_data = hmac.new(sk.to_string(), data, hashlib.sha512).digest()
            child_key = int.from_bytes(hmac_data[:32], byteorder='big')
            
            n = self.curve.generator.order()
            child_key = (child_key + int.from_bytes(sk.to_string(), byteorder='big')) % n
            
            if child_key == 0:
                raise BIP32PAError("Invalid derived key")
                
            return SigningKey.from_string(child_key.to_bytes(32, byteorder='big'), curve=self.curve)
        except Exception as e:
            raise BIP32PAError(f"Key derivation failed: {str(e)}")
    
    def _public_key_rerand(self, pk: VerifyingKey, data: bytes) -> VerifyingKey:
        try:
            pk_bytes = pk.to_string()
            
            hmac_data = hmac.new(pk_bytes, data, hashlib.sha512).digest()
            
            h = int.from_bytes(hmac_data[:32], byteorder='big')
            n = self.curve.generator.order()
            scalar = h % n
            
            point = scalar * self.curve.generator
            
            pk_new_bytes = point.to_bytes()
            pk_new = VerifyingKey.from_string(pk_new_bytes, curve=self.curve)
            
            return pk_new
        except Exception as e:
            raise BIP32PAError(f"Public key rerandomization failed: {str(e)}")
    
    def generate_master_key(self) -> MasterKey:
        try:
            seed = os.urandom(32)
            sk = SigningKey.generate(curve=self.curve)
            pk = sk.get_verifying_key()
            chaincode = os.urandom(32)
            
            return MasterKey(sk=sk, pk=pk, chaincode=chaincode, seed=seed)
        except Exception as e:
            raise BIP32PAError(f"Master key generation failed: {str(e)}")
    
    def revoke(self, msk: MasterKey) -> RevocationKey:
        try:
            return RevocationKey(pk=msk.pk, chaincode=msk.chaincode)
        except Exception as e:
            raise BIP32PAError(f"Revocation key generation failed: {str(e)}")
    
    def check_cred(self, id_s: str, cred: Credential, rk: RevocationKey) -> bool:
        try:
            derivation_data = self._h(rk.pk, rk.chaincode, id_s)
            pk_prime = self._public_key_rerand(rk.pk, derivation_data)
            
            return pk_prime.to_string() == cred.pk.to_string()
        except Exception as e:
            raise BIP32PAError(f"Credential check failed: {str(e)}")
    
    def simulate_revocation_check(self, database_size: int, blocklist_size: int) -> float:
        try:
            msk = self.generate_master_key()
            rk = self.revoke(msk)
            server_id = "server1"
            
            comparisons = int(self._log2(database_size))
            
            random_pk = SigningKey.generate(curve=self.curve).get_verifying_key()
            
            start_time = time.time()
            
            derivation_data = self._h(rk.pk, rk.chaincode, server_id)
            pk_prime = self._public_key_rerand(rk.pk, derivation_data)
            
            for _ in range(blocklist_size):
                for _ in range(comparisons):
                    _ = (pk_prime.to_string() == random_pk.to_string())
            
            end_time = time.time()
            
            return end_time - start_time
        except Exception as e:
            raise BIP32PAError(f"Simulation of revocation check failed: {str(e)}")
    
    def _log2(self, n: int) -> float:
        import math
        return math.log2(n) 