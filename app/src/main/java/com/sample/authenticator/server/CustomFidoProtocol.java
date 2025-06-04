package com.sample.authenticator.server;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;


public class CustomFidoProtocol {
    

    private static TokenMasterKey tokenMasterKey;
    

    static {
        tokenMasterKey = TokenMasterKey.create();
    }
    

    public static class ChallengeResult {
        private final byte[] challenge;
        private final byte[] state;
        
        public ChallengeResult(byte[] challenge, byte[] state) {
            this.challenge = challenge;
            this.state = state;
        }
        
        public byte[] getChallenge() {
            return challenge;
        }
        
        public byte[] getState() {
            return state;
        }
    }
    

    public static ChallengeResult rchall(byte[] idS) {

        byte[] rsR = CustomCryptoUtils.generateRandomBytes(32);
        byte[] rsA = CustomCryptoUtils.generateRandomBytes(32);
        

        byte[] c = CustomCryptoUtils.concat(idS, 
                   CustomCryptoUtils.concat(rsR, rsA));
        byte[] st = Arrays.copyOf(c, c.length);
        
        return new ChallengeResult(c, st);
    }
    

    public static class CommitResult {
        private final byte[] mHatR;
        
        public CommitResult(byte[] mHatR) {
            this.mHatR = mHatR;
        }
        
        public byte[] getMHatR() {
            return mHatR;
        }
    }
    

    public static CommitResult rcomm(byte[] idS, byte[] c) {

        byte[] id = Arrays.copyOf(c, idS.length);
        

        if (!Arrays.equals(id, idS)) {
            throw new IllegalArgumentException("The server ID does not match");
        }
        
        int offset = idS.length;
        byte[] rsR = Arrays.copyOfRange(c, offset, offset + 32);
        offset += 32;
        byte[] rsA = Arrays.copyOfRange(c, offset, offset + 32);

        byte[] mR = CustomCryptoUtils.H_0(rsR);
        byte[] mA = CustomCryptoUtils.H_0(rsA);

        byte[] mHatR = CustomCryptoUtils.concat(mR, mA);
        
        return new CommitResult(mHatR);
    }

    public static class ResponseResult {
        private final byte[] cid;
        private final byte[] rHatR;
        
        public ResponseResult(byte[] cid, byte[] rHatR) {
            this.cid = cid;
            this.rHatR = rHatR;
        }
        
        public byte[] getCid() {
            return cid;
        }
        
        public byte[] getRHatR() {
            return rHatR;
        }
    }
    

    public static ResponseResult rresp(byte[] idS, byte[] mHatR) {

        PrivateKey sk0 = tokenMasterKey.getSk0();
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] seed = tokenMasterKey.getSeed();
        byte[] lrev = tokenMasterKey.getLrev();
        

        byte[] cid = CustomCryptoUtils.H_1(seed, idS);
        

        cid = CustomCryptoUtils.Enc(ch, lrev);
        

        byte[] r = Arrays.copyOf(cid, cid.length);
        lrev = Arrays.copyOf(cid, cid.length);
        tokenMasterKey.setLrev(lrev);

        r = CustomCryptoUtils.Enc(ch, lrev);
        lrev = Arrays.copyOf(r, r.length);
        tokenMasterKey.setLrev(lrev);

        byte[] idSAndR = CustomCryptoUtils.concat(idS, r);
        cid = CustomCryptoUtils.Enc(seed, idSAndR);

        byte[] mR = Arrays.copyOf(mHatR, mHatR.length / 2);
        byte[] mA = Arrays.copyOfRange(mHatR, mHatR.length / 2, mHatR.length);
        

        byte[] pkBytes = pk0.getEncoded();
        byte[] skSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, idS);
        PrivateKey sk = KeyRandomizer.RandSK(sk0, skSeed);

        byte[] pkSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, idS);
        PublicKey pk = KeyRandomizer.RandPK(pk0, pkSeed);

        byte[] idSHash = CustomCryptoUtils.H_0(idS);
        byte[] pkEncoded = pk.getEncoded();
        byte[] mRMessage = CustomCryptoUtils.concat(idSHash, 
                         CustomCryptoUtils.concat(cid, 
                         CustomCryptoUtils.concat(pkEncoded, mR)));
        

        byte[] mAMessage = CustomCryptoUtils.concat(idSHash, mA);
        

        byte[] coinsR = CustomCryptoUtils.H_1(seed, mRMessage);
        byte[] coinsA = CustomCryptoUtils.H_1(seed, mAMessage);
        

        byte[] sigmaR = SignatureUtils.sig(sk, mRMessage, coinsR);
        byte[] sigmaA = SignatureUtils.sig(sk, mAMessage, coinsA);
        

        byte[] lk = CustomCryptoUtils.PRF(seed, cid, idS, mA);
        

        byte[] lkHash = CustomCryptoUtils.H_hat(lk);
        byte[] mAAndSigmaA = CustomCryptoUtils.concat(mA, sigmaA);
        byte[] sigmaAHat = CustomCryptoUtils.xor(lkHash, mAAndSigmaA);
        

        byte[] rHatR = CustomCryptoUtils.concat(pkEncoded, 
                    CustomCryptoUtils.concat(sigmaR, sigmaAHat));
        
        return new ResponseResult(cid, rHatR);
    }

    public static class DecapResult {
        private final byte[] rR;
        private final byte[] sigmaAHat;
        
        public DecapResult(byte[] rR, byte[] sigmaAHat) {
            this.rR = rR;
            this.sigmaAHat = sigmaAHat;
        }
        
        public byte[] getRR() {
            return rR;
        }
        
        public byte[] getSigmaAHat() {
            return sigmaAHat;
        }
    }
    

    public static DecapResult rdecap(byte[] cid, byte[] rHatR) {

        int pkLength = 150;
        

        byte[] pkEncoded = Arrays.copyOf(rHatR, pkLength);
        

        int sigLength = 100;
        byte[] sigmaR = Arrays.copyOfRange(rHatR, pkLength, pkLength + sigLength);
        byte[] sigmaAHat = Arrays.copyOfRange(rHatR, pkLength + sigLength, rHatR.length);
        

        byte[] rR = CustomCryptoUtils.concat(pkEncoded, sigmaR);
        

        ClientStorage.savePcs(cid, sigmaAHat);
        
        return new DecapResult(rR, sigmaAHat);
    }
    

    public static class CheckResult {
        private final boolean success;
        private final PublicKey pk;
        private final byte[] rsA;
        
        public CheckResult(boolean success, PublicKey pk, byte[] rsA) {
            this.success = success;
            this.pk = pk;
            this.rsA = rsA;
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public PublicKey getPk() {
            return pk;
        }
        
        public byte[] getRsA() {
            return rsA;
        }
    }
    

    public static CheckResult rcheck(byte[] st, byte[] cid, byte[] rR) {
        try {

            byte[] idS = Arrays.copyOf(st, 32);
            int offset = 32;
            byte[] rsR = Arrays.copyOfRange(st, offset, offset + 32);
            offset += 32;
            byte[] rsA = Arrays.copyOfRange(st, offset, offset + 32);
            

            int pkLength = 150;
            

            byte[] pkEncoded = Arrays.copyOf(rR, pkLength);
            byte[] sigmaR = Arrays.copyOfRange(rR, pkLength, rR.length);
            

            PublicKey pk = null;
            try {
                java.security.KeyFactory kf = java.security.KeyFactory.getInstance("EC");
                java.security.spec.X509EncodedKeySpec pkSpec = new java.security.spec.X509EncodedKeySpec(pkEncoded);
                pk = kf.generatePublic(pkSpec);
            } catch (Exception e) {
                throw new RuntimeException("The public key cannot be restored.\n", e);
            }
            

            byte[] idSHash = CustomCryptoUtils.H_0(idS);
            byte[] rsRHash = CustomCryptoUtils.H_0(rsR);
            byte[] mRMessage = CustomCryptoUtils.concat(idSHash, 
                             CustomCryptoUtils.concat(cid, 
                             CustomCryptoUtils.concat(pkEncoded, rsRHash)));
            

            boolean b = SignatureUtils.ver(pk, sigmaR, mRMessage);
            
            if (!b) {
                return new CheckResult(false, null, null);
            }

            ServerStorage.saveRcs(cid, pk, rsA);
            
            return new CheckResult(true, pk, rsA);
        } catch (Exception e) {
            return new CheckResult(false, null, null);
        }
    }
    

    public static class AuthChallengeResult {
        private final byte[] challenge;
        private final byte[] state;
        
        public AuthChallengeResult(byte[] challenge, byte[] state) {
            this.challenge = challenge;
            this.state = state;
        }
        
        public byte[] getChallenge() {
            return challenge;
        }
        
        public byte[] getState() {
            return state;
        }
    }
    

    public static AuthChallengeResult achall(byte[] cid, byte[] idS) {
        ServerStorage.ServerContext context = ServerStorage.getRcs(cid);
        if (context == null) {
            throw new IllegalArgumentException("The registration information corresponding to the credential ID was not found.\n");
        }
        
        byte[] rsA = context.getRsA();
        

        byte[] rsANew = CustomCryptoUtils.generateRandomBytes(32);
        

        byte[] c = CustomCryptoUtils.concat(idS, 
               CustomCryptoUtils.concat(rsA, rsANew));
        byte[] st = Arrays.copyOf(c, c.length);
        
        return new AuthChallengeResult(c, st);
    }

    public static class AuthCommitResult {
        private final byte[] mHatA;
        
        public AuthCommitResult(byte[] mHatA) {
            this.mHatA = mHatA;
        }
        
        public byte[] getMHatA() {
            return mHatA;
        }
    }
    

    public static AuthCommitResult acomm(byte[] idS, byte[] cid, byte[] c) {

        byte[] id = Arrays.copyOf(c, idS.length);

        if (!Arrays.equals(id, idS)) {
            throw new IllegalArgumentException("The server ID does not match");
        }
        
        int offset = idS.length;
        byte[] rsA = Arrays.copyOfRange(c, offset, offset + 32);
        offset += 32;
        byte[] rsANew = Arrays.copyOfRange(c, offset, offset + 32);
        

        byte[] mA = CustomCryptoUtils.H_0(rsA);
        

        byte[] sigmaAHat = ClientStorage.getPcs(cid);
        if (sigmaAHat == null) {
            throw new IllegalArgumentException("The client storage information corresponding to the credential ID was not found");
        }
        

        byte[] mANew = CustomCryptoUtils.H_0(rsANew);
        

        byte[] mHatA = CustomCryptoUtils.concat(mA, 
                     CustomCryptoUtils.concat(sigmaAHat, mANew));
        
        return new AuthCommitResult(mHatA);
    }
    

    public static class AuthResponseResult {
        private final byte[] rA;
        private final byte[] rHatA;
        
        public AuthResponseResult(byte[] rA, byte[] rHatA) {
            this.rA = rA;
            this.rHatA = rHatA;
        }
        
        public byte[] getRA() {
            return rA;
        }
        
        public byte[] getRHatA() {
            return rHatA;
        }
    }
    

    public static AuthResponseResult aresp(byte[] idS, byte[] cid, byte[] mHatA) {

        byte[] seed = tokenMasterKey.getSeed();
        byte[] ch = tokenMasterKey.getCh();
        PrivateKey sk0 = tokenMasterKey.getSk0();
        PublicKey pk0 = tokenMasterKey.getPk0();
        
        try {

            byte[] idAndR = CustomCryptoUtils.Dec(seed, cid);

            byte[] id = Arrays.copyOf(idAndR, idS.length);
            byte[] r = Arrays.copyOfRange(idAndR, idS.length, idAndR.length);
            

            if (!Arrays.equals(id, idS)) {
                throw new IllegalArgumentException("The server ID does not match.");
            }
            

            int maLength = 32;
            byte[] mA = Arrays.copyOf(mHatA, maLength);
            

            int sigmaAHatLength = 200;
            byte[] sigmaAHat = Arrays.copyOfRange(mHatA, maLength, maLength + sigmaAHatLength);
            
            byte[] mANew = Arrays.copyOfRange(mHatA, maLength + sigmaAHatLength, mHatA.length);
            

            byte[] lk = CustomCryptoUtils.PRF(seed, cid, idS, mA);
            

            byte[] lkHash = CustomCryptoUtils.H_hat(lk);
            byte[] mAndSigmaA = CustomCryptoUtils.xor(lkHash, sigmaAHat);
            

            byte[] m = Arrays.copyOf(mAndSigmaA, maLength);
            byte[] sigmaA = Arrays.copyOfRange(mAndSigmaA, maLength, mAndSigmaA.length);
            

            if (!Arrays.equals(m, mA)) {
                throw new IllegalArgumentException("Message verification failed");
            }
            

            byte[] rA = sigmaA;
            

            

            byte[] pkBytes = pk0.getEncoded();
            byte[] skSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, idS);
            PrivateKey sk = KeyRandomizer.RandSK(sk0, skSeed);
            

            byte[] idSHash = CustomCryptoUtils.H_0(idS);
            byte[] mANewMessage = CustomCryptoUtils.concat(idSHash, mANew);
            

            byte[] coinsANew = CustomCryptoUtils.H_1(seed, mANewMessage);
            

            byte[] sigmaANew = SignatureUtils.sig(sk, mANewMessage, coinsANew);
            

            byte[] lkNew = CustomCryptoUtils.PRF(seed, cid, idS, mANew);
            

            byte[] lkNewHash = CustomCryptoUtils.H_hat(lkNew);
            byte[] mANewAndSigmaANew = CustomCryptoUtils.concat(mANew, sigmaANew);
            byte[] sigmaAHatNew = CustomCryptoUtils.xor(lkNewHash, mANewAndSigmaANew);
            

            byte[] rHatA = sigmaAHatNew;
            
            return new AuthResponseResult(rA, rHatA);
        } catch (Exception e) {

            return null;
        }
    }
    

    public static boolean acheck(byte[] st, byte[] cid, byte[] rA) {
        try {

            byte[] idS = Arrays.copyOf(st, 32);
            int offset = 64;
            byte[] rsANew = Arrays.copyOfRange(st, offset, offset + 32);
            

            ServerStorage.ServerContext context = ServerStorage.getRcs(cid);
            if (context == null) {
                return false;
            }
            PublicKey pk = context.getPk();
            byte[] rsA = context.getRsA();
            

            byte[] idSHash = CustomCryptoUtils.H_0(idS);
            byte[] rsAHash = CustomCryptoUtils.H_0(rsA);
            byte[] mAMessage = CustomCryptoUtils.concat(idSHash, rsAHash);
            

            boolean b = SignatureUtils.ver(pk, rA, mAMessage);
            
            if (!b) {
                return false;
            }
            

            ServerStorage.updateRcs(cid, pk, rsANew);
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    

    public static void updateClientStorage(byte[] cid, byte[] rHatA) {
        // 更新pcs[cid]=σ^_a'
        ClientStorage.updatePcs(cid, rHatA);
    }
} 