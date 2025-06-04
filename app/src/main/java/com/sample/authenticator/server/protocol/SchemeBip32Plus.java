package com.sample.authenticator.server.protocol;

import android.util.Log;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

import com.sample.authenticator.server.ByteUtils;
import com.sample.authenticator.server.ClientStorage;
import com.sample.authenticator.server.CustomCryptoUtils;
import com.sample.authenticator.server.KeyRandomizer;
import com.sample.authenticator.server.ServerStorage;
import com.sample.authenticator.server.TokenMasterKey;


public class SchemeBip32Plus implements FidoProtocolScheme {
    private static final String TAG = "SchemeBip32Plus";

    private final TokenMasterKey tokenMasterKey;
    

    public SchemeBip32Plus() {
        this.tokenMasterKey = TokenMasterKey.create();
        Log.d(TAG, "Created BIP32+ scheme instance, generated master key");
    }
    
    @Override
    public String getSchemeName() {
        return "Scheme 6: BIP32+ Offline Update Scheme";
    }
    
    @Override
    public ChallengeResult generateRegistrationChallenge(byte[] serverId) {

        byte[] rsR = CustomCryptoUtils.generateRandomBytes(32);
        byte[] rsA = CustomCryptoUtils.generateRandomBytes(32);

        byte[] challenge = CustomCryptoUtils.concat(serverId, 
                          CustomCryptoUtils.concat(rsR, rsA));
        byte[] state = Arrays.copyOf(challenge, challenge.length);
        
        Log.d(TAG, "Generated registration challenge, server ID: " + ByteUtils.toHex(serverId));
        return new ChallengeResult(challenge, state);
    }
    
    @Override
    public CommitmentResult computeRegistrationCommitment(byte[] serverId, byte[] challenge) {

        int serverIdLength = serverId.length;
        byte[] id = Arrays.copyOf(challenge, serverIdLength);

        if (!Arrays.equals(id, serverId)) {
            Log.e(TAG, "Server ID mismatch");
            throw new IllegalArgumentException("Server ID mismatch");
        }

        int rsLength = (challenge.length - serverIdLength) / 2;
        byte[] rsR = Arrays.copyOfRange(challenge, serverIdLength, serverIdLength + rsLength);
        byte[] rsA = Arrays.copyOfRange(challenge, serverIdLength + rsLength, challenge.length);
        
        byte[] mR = CustomCryptoUtils.H_0(rsR);
        byte[] mA = CustomCryptoUtils.H_0(rsA);

        byte[] mHatR = CustomCryptoUtils.concat(mR, mA);
        
        Log.d(TAG, "Computed registration commitment, M_r: " + ByteUtils.toHex(mR) + ", M_a: " + ByteUtils.toHex(mA));
        return new CommitmentResult(mHatR);
    }
    
    @Override
    public TokenResponseResult generateRegistrationResponse(byte[] serverId, byte[] commitment) {

        PrivateKey sk0 = tokenMasterKey.getSk0();
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] seed = tokenMasterKey.getSeed();

        byte[] cid = CustomCryptoUtils.H_1(seed, serverId);

        byte[] mHatR = commitment;
        int mLength = mHatR.length / 2;
        byte[] mR = Arrays.copyOf(mHatR, mLength);
        byte[] mA = Arrays.copyOfRange(mHatR, mLength, mHatR.length);

        byte[] pkBytes = pk0.getEncoded();
        byte[] skSeed = CustomCryptoUtils.H_1(pkBytes, ch, serverId);
        PrivateKey sk = KeyRandomizer.RandSK(sk0, skSeed);

        byte[] pkSeed = CustomCryptoUtils.H_1(pkBytes, ch, serverId);
        PublicKey pk = KeyRandomizer.RandPK(pk0, pkSeed);
        byte[] pkEncoded = pk.getEncoded();

        byte[] idSHash = CustomCryptoUtils.H_0(serverId);
        byte[] mRMessage = CustomCryptoUtils.concat(idSHash, 
                         CustomCryptoUtils.concat(cid, 
                         CustomCryptoUtils.concat(pkEncoded, mR)));

        byte[] mAMessage = CustomCryptoUtils.concat(idSHash, mA);

        byte[] coinsR = CustomCryptoUtils.H_1(seed, mRMessage);
        byte[] coinsA = CustomCryptoUtils.H_1(seed, mAMessage);

        byte[] sigmaR = CustomCryptoUtils.sign(sk, mRMessage, coinsR);
        byte[] sigmaA = CustomCryptoUtils.sign(sk, mAMessage, coinsA);

        byte[] lk = CustomCryptoUtils.PRF(seed, cid, serverId, mA);

        byte[] lkHash = CustomCryptoUtils.H_hat(lk);
        byte[] mAAndSigmaA = CustomCryptoUtils.concat(mA, sigmaA);
        byte[] sigmaAHat = CustomCryptoUtils.xor(lkHash, mAAndSigmaA);

        byte[] rHatR = CustomCryptoUtils.concat(pkEncoded, 
                     CustomCryptoUtils.concat(sigmaR, sigmaAHat));
        
        Log.d(TAG, "Generated registration response, cid: " + ByteUtils.toHex(cid));
        return new TokenResponseResult(cid, rHatR);
    }
    
    @Override
    public DecapResult processRegistrationTokenResponse(byte[] credentialId, byte[] tokenResponse) {
        try {
            int pkLength = 150;
            int sigRLength = 200;

            byte[] pkEncoded = Arrays.copyOf(tokenResponse, pkLength);

            byte[] sigmaR = Arrays.copyOfRange(tokenResponse, pkLength, pkLength + sigRLength);

            byte[] sigmaAHat = Arrays.copyOfRange(tokenResponse, pkLength + sigRLength, tokenResponse.length);

            byte[] rR = CustomCryptoUtils.concat(pkEncoded, sigmaR);

            ClientStorage.saveCredentialData(credentialId, sigmaAHat);
            
            Log.d(TAG, "Processed registration token response, saved client state");
            return new DecapResult(rR, sigmaAHat);
        } catch (Exception e) {
            Log.e(TAG, "Processing registration token response exception: " + e.getMessage());
            throw new RuntimeException("Failed to process registration token response", e);
        }
    }
    
    @Override
    public VerificationResult verifyRegistration(byte[] state, byte[] credentialId, byte[] clientResponse) {
        try {
            int serverIdLength = 32;
            int rsLength = (state.length - serverIdLength) / 2;
            
            byte[] serverId = Arrays.copyOf(state, serverIdLength);
            byte[] rsR = Arrays.copyOfRange(state, serverIdLength, serverIdLength + rsLength);
            byte[] rsA = Arrays.copyOfRange(state, serverIdLength + rsLength, state.length);

            int pkLength = 150;
            
            byte[] pkEncoded = Arrays.copyOf(clientResponse, pkLength);
            byte[] sigmaR = Arrays.copyOfRange(clientResponse, pkLength, clientResponse.length);

            PublicKey pk = CustomCryptoUtils.bytesToPublicKey(pkEncoded);

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] mR = CustomCryptoUtils.H_0(rsR);
            byte[] mRMessage = CustomCryptoUtils.concat(idSHash, 
                             CustomCryptoUtils.concat(credentialId, 
                             CustomCryptoUtils.concat(pkEncoded, mR)));

            boolean isValid = CustomCryptoUtils.verify(pk, sigmaR, mRMessage);
            
            if (!isValid) {
                Log.e(TAG, "Registration verification failed, invalid signature");
                return new VerificationResult(false, null, null);
            }

            ServerStorage.saveRcs(credentialId, pk, rsA);
            
            Log.d(TAG, "Registration verification successful, saved server context");
            return new VerificationResult(true, pk, null);
        } catch (Exception e) {
            Log.e(TAG, "Registration verification exception: " + e.getMessage());
            return new VerificationResult(false, null, null);
        }
    }
    
    @Override
    public ChallengeResult generateAuthenticationChallenge(byte[] credentialId, byte[] serverId) {
        try {
            ServerStorage.ServerContext context = ServerStorage.getRcs(credentialId);
            if (context == null) {
                Log.e(TAG, "No server context found for credential ID");
                throw new IllegalArgumentException("No valid registration context found");
            }
            
            byte[] rsA = context.getExtraData();

            byte[] rsAPrime = CustomCryptoUtils.generateRandomBytes(32);

            byte[] challenge = CustomCryptoUtils.concat(serverId, 
                              CustomCryptoUtils.concat(rsA, rsAPrime));
            byte[] state = Arrays.copyOf(challenge, challenge.length);
            
            Log.d(TAG, "Generated authentication challenge, server ID: " + ByteUtils.toHex(serverId));
            return new ChallengeResult(challenge, state);
        } catch (Exception e) {
            Log.e(TAG, "Authentication challenge generation exception: " + e.getMessage());
            throw new RuntimeException("Failed to generate authentication challenge", e);
        }
    }
    
    @Override
    public CommitmentResult computeAuthenticationCommitment(byte[] serverId, byte[] credentialId, byte[] challenge) {
        try {
            int serverIdLength = serverId.length;
            byte[] id = Arrays.copyOf(challenge, serverIdLength);

            if (!Arrays.equals(id, serverId)) {
                Log.e(TAG, "Server ID mismatch in authentication");
                throw new IllegalArgumentException("Server ID mismatch");
            }
            
            int rsLength = (challenge.length - serverIdLength) / 2;
            byte[] rsA = Arrays.copyOfRange(challenge, serverIdLength, serverIdLength + rsLength);
            byte[] rsAPrime = Arrays.copyOfRange(challenge, serverIdLength + rsLength, challenge.length);

            byte[] mA = CustomCryptoUtils.H_0(rsA);

            byte[] sigmaAHat = ClientStorage.getCredentialData(credentialId);
            if (sigmaAHat == null) {
                Log.e(TAG, "No client state found for credential ID");
                throw new IllegalArgumentException("No valid client state found");
            }

            byte[] mAPrime = CustomCryptoUtils.H_0(rsAPrime);

            byte[] mHatA = CustomCryptoUtils.concat(mA, 
                          CustomCryptoUtils.concat(sigmaAHat, mAPrime));
            
            Log.d(TAG, "Computed authentication commitment, M_a: " + ByteUtils.toHex(mA) + ", M'_a: " + ByteUtils.toHex(mAPrime));
            return new CommitmentResult(mHatA);
        } catch (Exception e) {
            Log.e(TAG, "Authentication commitment exception: " + e.getMessage());
            throw new RuntimeException("Failed to compute authentication commitment", e);
        }
    }
    
    @Override
    public TokenResponseResult generateAuthenticationResponse(byte[] serverId, byte[] credentialId, byte[] commitment) {
        try {
            PrivateKey sk0 = tokenMasterKey.getSk0();
            PublicKey pk0 = tokenMasterKey.getPk0();
            byte[] ch = tokenMasterKey.getCh();
            byte[] seed = tokenMasterKey.getSeed();

            byte[] expectedCid = CustomCryptoUtils.H_1(seed, serverId);
            if (!Arrays.equals(credentialId, expectedCid)) {
                Log.e(TAG, "Credential ID verification failed");
                throw new IllegalArgumentException("Credential ID verification failed");
            }

            int mALength = 32;
            int sigmaAHatLength = 232;
            
            byte[] mA = Arrays.copyOf(commitment, mALength);
            byte[] sigmaAHat = Arrays.copyOfRange(commitment, mALength, mALength + sigmaAHatLength);
            byte[] mAPrime = Arrays.copyOfRange(commitment, mALength + sigmaAHatLength, commitment.length);

            byte[] lk = CustomCryptoUtils.PRF(seed, credentialId, serverId, mA);

            byte[] lkHash = CustomCryptoUtils.H_hat(lk);
            byte[] mAndSigmaA = CustomCryptoUtils.xor(lkHash, sigmaAHat);

            byte[] m = Arrays.copyOf(mAndSigmaA, mALength);
            byte[] sigmaA = Arrays.copyOfRange(mAndSigmaA, mALength, mAndSigmaA.length);

            if (!Arrays.equals(m, mA)) {
                Log.e(TAG, "M_a mismatch in authentication");
                throw new IllegalArgumentException("M_a mismatch");
            }
            

            byte[] pkBytes = pk0.getEncoded();
            byte[] derivationSeed = CustomCryptoUtils.H_1(pkBytes, ch, serverId);
            

            PrivateKey sk = KeyRandomizer.RandSK(sk0, derivationSeed);
            

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] mAPrimeMessage = CustomCryptoUtils.concat(idSHash, mAPrime);
            

            byte[] coinsAPrime = CustomCryptoUtils.H_1(seed, mAPrimeMessage);
            

            byte[] sigmaAPrime = CustomCryptoUtils.sign(sk, mAPrimeMessage, coinsAPrime);

            byte[] lkPrime = CustomCryptoUtils.PRF(seed, credentialId, serverId, mAPrime);
            

            byte[] lkPrimeHash = CustomCryptoUtils.H_hat(lkPrime);
            byte[] mAPrimeAndSigmaAPrime = CustomCryptoUtils.concat(mAPrime, sigmaAPrime);
            byte[] sigmaAPrimeHat = CustomCryptoUtils.xor(lkPrimeHash, mAPrimeAndSigmaAPrime);

            
            ClientStorage.saveCredentialData(credentialId, sigmaAPrimeHat);
            
            Log.d(TAG, "Generated authentication response, updated client state");
            return new TokenResponseResult(credentialId, sigmaAPrime);
        } catch (Exception e) {
            Log.e(TAG, "Authentication response generation exception: " + e.getMessage());
            throw new RuntimeException("Failed to generate authentication response", e);
        }
    }
    
    @Override
    public boolean verifyAuthentication(byte[] state, byte[] credentialId, byte[] clientResponse) {
        try {
            int serverIdLength = 32;
            int rsLength = (state.length - serverIdLength) / 2;
            
            byte[] serverId = Arrays.copyOf(state, serverIdLength);
            byte[] rsA = Arrays.copyOfRange(state, serverIdLength, serverIdLength + rsLength);
            byte[] rsAPrime = Arrays.copyOfRange(state, serverIdLength + rsLength, state.length);

            ServerStorage.ServerContext context = ServerStorage.getRcs(credentialId);
            if (context == null) {
                Log.e(TAG, "No server context found for credential ID");
                return false;
            }
            
            PublicKey pk = context.getPublicKey();

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] mA = CustomCryptoUtils.H_0(rsA);
            byte[] mAMessage = CustomCryptoUtils.concat(idSHash, mA);

            byte[] sigmaA = clientResponse;
            boolean isValid = CustomCryptoUtils.verify(pk, sigmaA, mAMessage);
            
            if (isValid) {
                ServerStorage.saveRcs(credentialId, pk, rsAPrime);
                
                Log.d(TAG, "Authentication verification successful, updated server context");
            } else {
                Log.e(TAG, "Authentication verification failed, invalid signature");
            }
            
            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "Authentication verification exception: " + e.getMessage());
            return false;
        }
    }
    
    @Override
    public void updateClientStorage(byte[] credentialId, byte[] newData) {

        ClientStorage.saveCredentialData(credentialId, newData);
        Log.d(TAG, "Updated client storage for credential ID: " + ByteUtils.toHex(credentialId));
    }
    
    @Override
    public void clearStorage() {
        Log.d(TAG, "Clearing storage for BIP32+ scheme");
        
        try {
            ClientStorage.clear();
            ServerStorage.clear();
        } catch (Exception e) {
            Log.e(TAG, "Error clearing storage: " + e.getMessage());
        }
    }

    public byte[] generateRevocationKey() {
        try {
            byte[] seed = tokenMasterKey.getSeed();
            byte[] revKey = new byte[32];
            
            System.arraycopy(seed, 0, revKey, 0, Math.min(seed.length, revKey.length));
            
            byte[] revocationKey = CustomCryptoUtils.H_1(revKey, "global_revocation".getBytes());
            
            Log.d(TAG, "Generated global revocation key: " + ByteUtils.toHex(revocationKey));
            return revocationKey;
        } catch (Exception e) {
            Log.e(TAG, "Error generating revocation key: " + e.getMessage());
            return null;
        }
    }
    

    public boolean checkCredential(byte[] serverId, byte[] credential, byte[] revocationKey) {
        try {
            byte[] seed = tokenMasterKey.getSeed();
            byte[] expectedKey = CustomCryptoUtils.H_1(seed, "global_revocation".getBytes());
            
            if (!Arrays.equals(revocationKey, expectedKey)) {
                Log.e(TAG, "Invalid revocation key");
                return false;
            }
            
            byte[] cid = CustomCryptoUtils.H_1(seed, serverId);
            boolean isValid = Arrays.equals(credential, cid);
            
            if (isValid) {
                Log.d(TAG, "Credential check successful");
            } else {
                Log.d(TAG, "Credential check failed");
            }
            
            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "Error checking credential: " + e.getMessage());
            return false;
        }
    }
} 