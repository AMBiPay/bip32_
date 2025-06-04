package com.sample.authenticator.server;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;


public class KeyRandomizer {
    

    public static PrivateKey RandSK(PrivateKey sk0, byte[] seed) {
        try {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(seed);
            keyGen.initialize(256, random);
            

            KeyPair keyPair = keyGen.generateKeyPair();
            return keyPair.getPrivate();
        } catch (Exception e) {
            throw new RuntimeException("Key randomization failed", e);
        }
    }
    

    public static PublicKey RandPK(PublicKey pk0, byte[] seed) {
        try {

            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            random.setSeed(seed);
            keyGen.initialize(256, random);
            

            KeyPair keyPair = keyGen.generateKeyPair();
            return keyPair.getPublic();
        } catch (Exception e) {
            throw new RuntimeException("Key randomization failed", e);
        }
    }
    

    public static KeyPair generateMasterKeyPair() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(256);
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate master key pair", e);
        }
    }
} 