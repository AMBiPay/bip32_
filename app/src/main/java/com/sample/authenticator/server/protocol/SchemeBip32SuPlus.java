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


public class SchemeBip32SuPlus implements FidoProtocolScheme {
    private static final String TAG = "SchemeBip32SuPlus";
    

    private final TokenMasterKey tokenMasterKey;

    public SchemeBip32SuPlus() {
        this.tokenMasterKey = TokenMasterKey.create();
        Log.d(TAG, "Create an instance of the BIP32-SU+ scheme and generate the master key");
    }
    
    @Override
    public String getSchemeName() {
        return "The Revocable Update Scheme of BIP32-SU+";
    }
    
    @Override
    public ChallengeResult generateRegistrationChallenge(byte[] serverId) {

        byte[] rsR = CustomCryptoUtils.generateRandomBytes(32);
        byte[] rsA = CustomCryptoUtils.generateRandomBytes(32);
        

        byte[] challenge = CustomCryptoUtils.concat(serverId, 
                          CustomCryptoUtils.concat(rsR, rsA));
        byte[] state = Arrays.copyOf(challenge, challenge.length);
        
        Log.d(TAG, "Generate the registration challenge and the server ID: " + ByteUtils.toHex(serverId));
        return new ChallengeResult(challenge, state);
    }
    
    @Override
    public CommitmentResult computeRegistrationCommitment(byte[] serverId, byte[] challenge) {

        int serverIdLength = serverId.length;
        byte[] id = Arrays.copyOf(challenge, serverIdLength);

        if (!Arrays.equals(id, serverId)) {
            Log.e(TAG, "The server ID does not match");
            throw new IllegalArgumentException("The server ID does not match");
        }

        int rsLength = (challenge.length - serverIdLength) / 2;
        byte[] rsR = Arrays.copyOfRange(challenge, serverIdLength, serverIdLength + rsLength);
        byte[] rsA = Arrays.copyOfRange(challenge, serverIdLength + rsLength, challenge.length);
        
        byte[] mR = CustomCryptoUtils.H_0(rsR);
        byte[] mA = CustomCryptoUtils.H_0(rsA);

        byte[] mHatR = CustomCryptoUtils.concat(mR, mA);
        
        Log.d(TAG, "Calculate the registration command.\n，M_r: " + ByteUtils.toHex(mR) + ", M_a: " + ByteUtils.toHex(mA));
        return new CommitmentResult(mHatR);
    }
    
    @Override
    public TokenResponseResult generateRegistrationResponse(byte[] serverId, byte[] commitment) {

        PrivateKey sk0 = tokenMasterKey.getSk0();
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] seed = tokenMasterKey.getSeed();
        byte[] lrev = tokenMasterKey.getLrev();

        byte[] r = CustomCryptoUtils.Enc(ch, lrev);

        lrev = Arrays.copyOf(r, r.length);
        tokenMasterKey.setLrev(lrev);

        byte[] idSAndR = CustomCryptoUtils.concat(serverId, r);
        byte[] cid = CustomCryptoUtils.Enc(seed, idSAndR);

        byte[] mHatR = commitment;
        int mLength = mHatR.length / 2;
        byte[] mR = Arrays.copyOf(mHatR, mLength);
        byte[] mA = Arrays.copyOfRange(mHatR, mLength, mHatR.length);

        byte[] pkBytes = pk0.getEncoded();
        byte[] skSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, serverId);
        PrivateKey sk = KeyRandomizer.RandSK(sk0, skSeed);

        byte[] pkSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, serverId);
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
        
        Log.d(TAG, "Generate the registration response，cid: " + ByteUtils.toHex(cid));
        return new TokenResponseResult(cid, rHatR);
    }
    
    @Override
    public DecapResult processRegistrationTokenResponse(byte[] credentialId, byte[] tokenResponse) {
        try {
            int pkLength = 150;
            int sigRLength = 200;
k
            byte[] pkEncoded = Arrays.copyOf(tokenResponse, pkLength);

            byte[] sigmaR = Arrays.copyOfRange(tokenResponse, pkLength, pkLength + sigRLength);

            byte[] sigmaAHat = Arrays.copyOfRange(tokenResponse, pkLength + sigRLength, tokenResponse.length);

            byte[] rR = CustomCryptoUtils.concat(pkEncoded, sigmaR);

            ClientStorage.saveCredentialData(credentialId, sigmaAHat);
            
            Log.d(TAG, "Process the registration token response and save the client status\n");
            return new DecapResult(rR, sigmaAHat);
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while processing the registration token response\n: " + e.getMessage());
            throw new RuntimeException("Failed to process the registration token response", e);
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
                Log.e(TAG, "The registration verification failed, and the signature is invalid");
                return new VerificationResult(false, null, null);
            }

            ServerStorage.saveRcs(credentialId, pk, rsA);
            
            Log.d(TAG, "The registration verification was successful, and the server context was saved");
            return new VerificationResult(true, pk, null);
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred during the registration verification: " + e.getMessage());
            return new VerificationResult(false, null, null);
        }
    }
    
    @Override
    public ChallengeResult generateAuthenticationChallenge(byte[] credentialId, byte[] serverId) {
        try {
            ServerStorage.ServerContext context = ServerStorage.getRcs(credentialId);
            if (context == null) {
                Log.e(TAG, "The server context corresponding to the credential ID was not found");
                throw new IllegalArgumentException("No valid registration context was found");
            }
            
            byte[] rsA = context.getExtraData();

            byte[] rsAPrime = CustomCryptoUtils.generateRandomBytes(32);

            byte[] challenge = CustomCryptoUtils.concat(serverId, 
                              CustomCryptoUtils.concat(rsA, rsAPrime));
            byte[] state = Arrays.copyOf(challenge, challenge.length);
            
            Log.d(TAG, "Generate the authentication challenge and the server ID: " + ByteUtils.toHex(serverId));
            return new ChallengeResult(challenge, state);
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while generating the authentication challenge: " + e.getMessage());
            throw new RuntimeException("Failed to generate the authentication challenge", e);
        }
    }
    
    @Override
    public CommitmentResult computeAuthenticationCommitment(byte[] serverId, byte[] credentialId, byte[] challenge) {
        try {
            int serverIdLength = serverId.length;
            byte[] id = Arrays.copyOf(challenge, serverIdLength);

            if (!Arrays.equals(id, serverId)) {
                Log.e(TAG, "The server ID does not match");
                throw new IllegalArgumentException("The server ID does not match");
            }
            
            int rsLength = (challenge.length - serverIdLength) / 2;
            byte[] rsA = Arrays.copyOfRange(challenge, serverIdLength, serverIdLength + rsLength);
            byte[] rsAPrime = Arrays.copyOfRange(challenge, serverIdLength + rsLength, challenge.length);

            byte[] mA = CustomCryptoUtils.H_0(rsA);

            byte[] sigmaAHat = ClientStorage.getCredentialData(credentialId);
            if (sigmaAHat == null) {
                Log.e(TAG, "The client status corresponding to the credential ID was not found");
                throw new IllegalArgumentException("No valid client status was found");
            }

            byte[] mAPrime = CustomCryptoUtils.H_0(rsAPrime);

            byte[] mHatA = CustomCryptoUtils.concat(mA, 
                          CustomCryptoUtils.concat(sigmaAHat, mAPrime));
            
            Log.d(TAG, "Calculate the authentication command");
            return new CommitmentResult(mHatA);
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while calculating the authentication command: " + e.getMessage());
            throw new RuntimeException("Failed to calculate the authentication command", e);
        }
    }
    
    @Override
    public TokenResponseResult generateAuthenticationResponse(byte[] serverId, byte[] credentialId, byte[] commitment) {
        try {
            PrivateKey sk0 = tokenMasterKey.getSk0();
            PublicKey pk0 = tokenMasterKey.getPk0();
            byte[] ch = tokenMasterKey.getCh();
            byte[] seed = tokenMasterKey.getSeed();

            byte[] decrypted = CustomCryptoUtils.Dec(seed, credentialId);

            int serverIdLength = 32;
            byte[] extractedId = Arrays.copyOf(decrypted, serverIdLength);
            byte[] r = Arrays.copyOfRange(decrypted, serverIdLength, decrypted.length);

            if (!Arrays.equals(extractedId, serverId)) {
                Log.e(TAG, "The server ID does not match");
                throw new IllegalArgumentException("The server ID does not match");
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
                Log.e(TAG, "The authentication message verification failed");
                throw new IllegalArgumentException("The authentication message verification failed");
            }

            byte[] pkBytes = pk0.getEncoded();
            byte[] derivationSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, serverId);
            

            PrivateKey sk = KeyRandomizer.RandSK(sk0, derivationSeed);
            

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] mAPrimeMessage = CustomCryptoUtils.concat(idSHash, mAPrime);
            

            byte[] coinsAPrime = CustomCryptoUtils.H_1(seed, mAPrimeMessage);
            

            byte[] sigmaAPrime = CustomCryptoUtils.sign(sk, mAPrimeMessage, coinsAPrime);
            

            byte[] lkPrime = CustomCryptoUtils.PRF(seed, credentialId, serverId, mAPrime);
            

            byte[] lkPrimeHash = CustomCryptoUtils.H_hat(lkPrime);
            byte[] mAPrimeAndSigmaAPrime = CustomCryptoUtils.concat(mAPrime, sigmaAPrime);
            byte[] sigmaAPrimeHat = CustomCryptoUtils.xor(lkPrimeHash, mAPrimeAndSigmaAPrime);
            

            
            Log.d(TAG, "Generate an authentication response, which is used for the current authentication and the preparation of the next authentication");
            return new TokenResponseResult(sigmaA, sigmaAPrimeHat);
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while generating the authentication response: " + e.getMessage());
            throw new RuntimeException("Failed to generate the authentication response", e);
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
                Log.e(TAG, "The server context corresponding to the credential ID was not found");
                return false;
            }
            
            PublicKey pk = context.getPk();
            

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] mA = CustomCryptoUtils.H_0(rsA);
            byte[] mAMessage = CustomCryptoUtils.concat(idSHash, mA);
            

            byte[] sigmaA = clientResponse;
            boolean isValid = CustomCryptoUtils.verify(pk, sigmaA, mAMessage);
            
            if (isValid) {

                ServerStorage.saveRcs(credentialId, pk, rsAPrime);
                
                Log.d(TAG, "The authentication verification was successful, and the server context was updated");
            } else {
                Log.e(TAG, "The authentication verification failed, and the signature is invalid");
            }
            
            return isValid;
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred during the authentication verification: " + e.getMessage());
            return false;
        }
    }
    
    @Override
    public void updateClientStorage(byte[] credentialId, byte[] newData) {

        ClientStorage.saveCredentialData(credentialId, newData);
        Log.d(TAG, "Update the client status and prepare for the next authentication");
    }
    
    @Override
    public void clearStorage() {

        ClientStorage.clear();
        ServerStorage.clear();
        Log.d(TAG, "Empty the storage");
    }
    

    public byte[] generateRevocationKey() {
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] lrev = tokenMasterKey.getLrev();

        byte[] pkBytes = pk0.getEncoded();
        byte[] revocationKey = CustomCryptoUtils.concat(pkBytes, 
                               CustomCryptoUtils.concat(ch, lrev));
        
        Log.d(TAG, "Generate the revocation key");
        return revocationKey;
    }
    

    public boolean checkCredential(byte[] serverId, byte[] credential, byte[] revocationKey) {
        try {

            int pkLength = 150;
            int chLength = 32;
            
            byte[] pkBytes = Arrays.copyOf(revocationKey, pkLength);
            byte[] ch = Arrays.copyOfRange(revocationKey, pkLength, pkLength + chLength);
            byte[] lrev = Arrays.copyOfRange(revocationKey, pkLength + chLength, revocationKey.length);

            PublicKey pk0 = CustomCryptoUtils.bytesToPublicKey(pkBytes);

            byte[] currentLrev = Arrays.copyOf(lrev, lrev.length);
            byte[] r;
            boolean needsRevocation = false;

            boolean isTerminalLrev = isTerminalLrevValue(currentLrev);
            
            while (!isTerminalLrev) {

                r = CustomCryptoUtils.Dec(ch, currentLrev);

                byte[] derivationSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, serverId);
                PublicKey derivedPk = KeyRandomizer.RandPK(pk0, derivationSeed);

                PublicKey credentialPk = CustomCryptoUtils.bytesToPublicKey(credential);

                if (derivedPk.equals(credentialPk)) {
                    needsRevocation = true;
                    break;
                }

                currentLrev = r;
                isTerminalLrev = isTerminalLrevValue(currentLrev);
            }
            
            Log.d(TAG, "Check whether the credential needs to be revoked: " + needsRevocation);
            return needsRevocation;
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while checking whether the credential needs to be revoked.\n: " + e.getMessage());
            return false;
        }
    }
    

    private boolean isTerminalLrevValue(byte[] lrev) {
        for (int i = 0; i < lrev.length - 1; i++) {
            if (lrev[i] != 0) {
                return false;
            }
        }

        return lrev[lrev.length - 1] == 1;
    }
} 