package com.sample.authenticator.server;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;


public class TokenMasterKey {
    private final PrivateKey sk0;
    private final PublicKey pk0;
    private final byte[] ch;
    private final byte[] seed;
    

    private byte[] lrev;
    

    public TokenMasterKey(KeyPair keyPair, byte[] ch, byte[] seed) {
        this.sk0 = keyPair.getPrivate();
        this.pk0 = keyPair.getPublic();
        this.ch = ch;
        this.seed = seed;
        this.lrev = new byte[32];
    }
    

    public static TokenMasterKey create() {
        KeyPair keyPair = KeyRandomizer.generateMasterKeyPair();
        byte[] ch = CustomCryptoUtils.generateRandomBytes(32);
        byte[] seed = CustomCryptoUtils.generateRandomBytes(32);
        return new TokenMasterKey(keyPair, ch, seed);
    }

    public PrivateKey getSk0() {
        return sk0;
    }

    public PublicKey getPk0() {
        return pk0;
    }

    public byte[] getCh() {
        return ch;
    }

    public byte[] getSeed() {
        return seed;
    }
    
    public byte[] getLrev() {
        return lrev;
    }
    
    public void setLrev(byte[] lrev) {
        this.lrev = lrev;
    }
} 