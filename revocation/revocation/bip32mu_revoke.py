#!/usr/bin/env python
# -*- coding: utf-8 -*-

import hashlib
import hmac
import os
import time
import random
import math
from dataclasses import dataclass
from typing import Tuple, Dict, Optional, Any, List

from ecdsa import SigningKey, VerifyingKey, SECP256k1
from ecdsa.util import sigencode_string, sigdecode_string
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class BIP32MUError(Exception):
    pass

@dataclass
class MasterKey:
    sk: SigningKey
    pk: VerifyingKey
    chaincode: bytes
    seed: bytes
    lrev: bytes

@dataclass
class RevocationKey:
    pk: VerifyingKey
    chaincode: bytes
    lrev: bytes

@dataclass
class Credential:
    cid: bytes
    pk: VerifyingKey
    server_id: str

class BIP32MURevoke:
    
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
                raise BIP32MUError("Invalid derived key")
                
            return SigningKey.from_string(child_key.to_bytes(32, byteorder='big'), curve=self.curve)
        except Exception as e:
            raise BIP32MUError(f"Key derivation failed: {str(e)}")
    
    def _decrypt(self, key: bytes, data: bytes) -> bytes:
        try:
            if len(data) < 16:
                data = data + b'\0' * (16 - len(data))
            
            iv = data[:16]
            ciphertext = data[16:]
            
            if not ciphertext:
                return os.urandom(16)
            
            if len(ciphertext) % 16 != 0:
                ciphertext = pad(ciphertext, 16)
            
            cipher = AES.new(key[:16], AES.MODE_CBC, iv)
            plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return plaintext
        except Exception as e:
            raise BIP32MUError(f"Decryption failed: {str(e)}")
    
    def generate_master_key(self) -> MasterKey:
        try:
            seed = os.urandom(32)
            sk = SigningKey.generate(curve=self.curve)
            pk = sk.get_verifying_key()
            chaincode = os.urandom(32)
            lrev = os.urandom(16)
            
            return MasterKey(sk=sk, pk=pk, chaincode=chaincode, seed=seed, lrev=lrev)
        except Exception as e:
            raise BIP32MUError(f"Master key generation failed: {str(e)}")
    
    def revoke(self, msk: MasterKey) -> RevocationKey:
        try:
            return RevocationKey(pk=msk.pk, chaincode=msk.chaincode, lrev=msk.lrev)
        except Exception as e:
            raise BIP32MUError(f"Revocation key generation failed: {str(e)}")
    
    def check_cred(self, id_s: str, cred: Credential, rk: RevocationKey) -> bool:
        try:
            pk_0 = rk.pk
            ch = rk.chaincode
            lrev = rk.lrev
            pk = cred.pk
            
            i = 0
            r = []
            
            zero_bytes = bytes([0] * (len(lrev) - 1)) + bytes([1])
            
            curr_lrev = lrev
            max_decryption = 5
            
            while i < max_decryption and curr_lrev != zero_bytes:
                r_i = self._decrypt(ch, curr_lrev)
                r.append(r_i)
                
                curr_lrev = r_i
                i += 1
            
            for j in range(len(r)):
                derivation_data = self._h(pk_0, ch, r[j], id_s)
                
                sk = SigningKey.generate(curve=self.curve)
                pk_prime = sk.get_verifying_key()
                
                if pk_prime.to_string() == pk.to_string():
                    return True
            
            return False
        except Exception as e:
            raise BIP32MUError(f"Credential check failed: {str(e)}")
            
    def simulate_revocation_check(self, database_size: int, blocklist_size: int) -> float:
        try:
            msk = self.generate_master_key()
            rk = self.revoke(msk)
            server_id = "server1"
            
            comparisons = int(self._log2(database_size))
            
            max_decryption = 5
            
            start_time = time.time()
            
            for _ in range(blocklist_size):
                lrev = rk.lrev
                r = []
                
                for i in range(max_decryption):
                    r_i = self._decrypt(rk.chaincode, lrev)
                    r.append(r_i)
                    lrev = r_i
                
                random_pk = SigningKey.generate(curve=self.curve).get_verifying_key()
                
                for r_i in r:
                    derivation_data = self._h(rk.pk, rk.chaincode, r_i, server_id)
                    
                    for _ in range(comparisons // max_decryption):
                        _ = (random_pk.to_string() == random_pk.to_string())
            
            end_time = time.time()
            
            return end_time - start_time
        except Exception as e:
            raise BIP32MUError(f"Simulation of revocation check failed: {str(e)}")
    
    def _log2(self, n: int) -> float:
        return math.log2(n) 