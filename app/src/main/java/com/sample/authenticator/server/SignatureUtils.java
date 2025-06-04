package com.sample.authenticator.server;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

public class SignatureUtils {
    

    public static byte[] sig(PrivateKey sk, byte[] message, byte[] coins) {
        try {

            Signature signature = Signature.getInstance("SHA256withECDSA");
            signature.initSign(sk);
            

            signature.update(message);
            

            return signature.sign();
        } catch (Exception e) {
            throw new RuntimeException("Signature generation failed", e);
        }
    }
    

    public static boolean ver(PublicKey pk, byte[] signature, byte[] message) {
        try {
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(pk);

            sig.update(message);

            return sig.verify(signature);
        } catch (Exception e) {
            throw new RuntimeException("Signature verification failed", e);
        }
    }
} 