package com.sample.authenticator.server;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class CustomCryptoUtils {
    

    public static byte[] H_0(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-256 algorithm not available", e);
        }
    }
    

    public static byte[] H_1(byte[] key, byte[]... inputs) {
        try {
            Mac hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec keySpec = new SecretKeySpec(key, "HmacSHA256");
            hmac.init(keySpec);
            
            for (byte[] input : inputs) {
                hmac.update(input);
            }
            
            return hmac.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException("HMAC-SHA256 algorithm not available", e);
        }
    }
    

    public static byte[] H_hat(byte[] input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-512");
            return digest.digest(input);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("SHA-512 algorithm not available", e);
        }
    }
    

    public static byte[] Enc(byte[] key, byte[] input) {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Generate random IV
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            
            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
            byte[] encrypted = cipher.doFinal(input);
            
            // Concatenate IV with encrypted data
            byte[] result = new byte[iv.length + encrypted.length];
            System.arraycopy(iv, 0, result, 0, iv.length);
            System.arraycopy(encrypted, 0, result, iv.length, encrypted.length);
            
            return result;
        } catch (Exception e) {
            throw new RuntimeException("Encryption failed", e);
        }
    }
    

    public static byte[] Dec(byte[] key, byte[] input) {
        try {
            SecretKey secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            
            // Extract IV from input
            byte[] iv = new byte[16];
            byte[] encrypted = new byte[input.length - 16];
            System.arraycopy(input, 0, iv, 0, iv.length);
            System.arraycopy(input, iv.length, encrypted, 0, encrypted.length);
            
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            
            return cipher.doFinal(encrypted);
        } catch (Exception e) {
            throw new RuntimeException("Decryption failed", e);
        }
    }
    

    public static byte[] PRF(byte[] key, byte[]... inputs) {
        return H_1(key, inputs); // Here HMAC-SHA256 is used as PRF
    }
    

    public static byte[] generateRandomBytes(int length) {
        byte[] random = new byte[length];
        new SecureRandom().nextBytes(random);
        return random;
    }
    

    public static byte[] xor(byte[] a, byte[] b) {
        if (a.length != b.length) {
            throw new IllegalArgumentException("Byte arrays have different lengths");
        }
        
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            result[i] = (byte) (a[i] ^ b[i]);
        }
        
        return result;
    }
    

    public static byte[] concat(byte[] a, byte[] b) {
        byte[] result = new byte[a.length + b.length];
        System.arraycopy(a, 0, result, 0, a.length);
        System.arraycopy(b, 0, result, a.length, b.length);
        return result;
    }
    

    public static byte[] sign(PrivateKey privateKey, byte[] message, byte[] randomCoins) {
        try {
            Signature signature = Signature.getInstance("SHA256withECDSA");
            

            signature.initSign(privateKey, new SecureRandom(randomCoins));

            signature.update(message);
            

            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Signing failed", e);
        }
    }
    

    public static boolean verify(PublicKey publicKey, byte[] signature, byte[] message) {
        try {

            Signature verifier = Signature.getInstance("SHA256withECDSA");
            

            verifier.initVerify(publicKey);
            

            verifier.update(message);
            

            return verifier.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("Signature verification failed", e);
        }
    }

    public static PublicKey bytesToPublicKey(byte[] bytes) {
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("EC");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(bytes);
            return keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("Public key conversion failed", e);
        }
    }
} 