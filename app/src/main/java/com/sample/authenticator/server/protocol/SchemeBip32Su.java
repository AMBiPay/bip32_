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


public class SchemeBip32Su implements FidoProtocolScheme {
    private static final String TAG = "SchemeBip32Su";

    private final TokenMasterKey tokenMasterKey;

    public SchemeBip32Su() {

        this.tokenMasterKey = TokenMasterKey.create();
        Log.d(TAG, "Created BIP32-SU scheme instance, generated master key");
    }
    
    @Override
    public String getSchemeName() {
        return "Scheme 3: BIP32-SU Deterministic Key Derivation Scheme";
    }
    
    @Override
    public ChallengeResult generateRegistrationChallenge(byte[] serverId) {
        byte[] rs = CustomCryptoUtils.generateRandomBytes(32);

        byte[] challenge = CustomCryptoUtils.concat(serverId, rs);
        byte[] state = Arrays.copyOf(challenge, challenge.length);
        
        Log.d(TAG, "Generated registration challenge, server ID: " + ByteUtils.toHex(serverId));
        return new ChallengeResult(challenge, state);
    }
    
    @Override
    public CommitmentResult computeRegistrationCommitment(byte[] serverId, byte[] challenge) {

        byte[] id = Arrays.copyOf(challenge, serverId.length);

        if (!Arrays.equals(id, serverId)) {
            Log.e(TAG, "Server ID mismatch");
            throw new IllegalArgumentException("Server ID mismatch");
        }
        
        byte[] rs = Arrays.copyOfRange(challenge, serverId.length, challenge.length);

        byte[] mr = CustomCryptoUtils.H_0(rs);
        
        Log.d(TAG, "Computed registration commitment, M_r: " + ByteUtils.toHex(mr));
        return new CommitmentResult(mr);
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

        byte[] pkBytes = pk0.getEncoded();
        byte[] derivationSeed = CustomCryptoUtils.H_1(pkBytes, ch, r, serverId);

        PrivateKey sk = KeyRandomizer.RandSK(sk0, derivationSeed);
        PublicKey pk = KeyRandomizer.RandPK(pk0, derivationSeed);

        byte[] idSHash = CustomCryptoUtils.H_0(serverId);
        byte[] pkEncoded = pk.getEncoded();
        byte[] mr = commitment;
        byte[] message = CustomCryptoUtils.concat(idSHash, 
                        CustomCryptoUtils.concat(cid, 
                        CustomCryptoUtils.concat(pkEncoded, mr)));

        byte[] coins = CustomCryptoUtils.H_1(seed, message);

        byte[] signature = CustomCryptoUtils.sign(sk, message, coins);

        byte[] response = CustomCryptoUtils.concat(pkEncoded, signature);
        
        Log.d(TAG, "Generated registration response, cid: " + ByteUtils.toHex(cid));
        return new TokenResponseResult(cid, response);
    }
    
    @Override
    public DecapResult processRegistrationTokenResponse(byte[] credentialId, byte[] tokenResponse) {

        
        Log.d(TAG, "Processed registration token response, credential ID: " + ByteUtils.toHex(credentialId));
        return new DecapResult(tokenResponse, null);
    }
    
    @Override
    public VerificationResult verifyRegistration(byte[] state, byte[] credentialId, byte[] clientResponse) {
        try {
            int serverIdLength = 32;
            
            byte[] serverId = Arrays.copyOf(state, serverIdLength);
            byte[] rs = Arrays.copyOfRange(state, serverIdLength, state.length);

            int pkLength = 150;
            byte[] pkEncoded = Arrays.copyOf(clientResponse, pkLength);
            byte[] signature = Arrays.copyOfRange(clientResponse, pkLength, clientResponse.length);

            PublicKey pk = CustomCryptoUtils.bytesToPublicKey(pkEncoded);

            byte[] mr = CustomCryptoUtils.H_0(rs);

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] message = CustomCryptoUtils.concat(idSHash, 
                           CustomCryptoUtils.concat(credentialId, 
                           CustomCryptoUtils.concat(pkEncoded, mr)));

            boolean isValid = CustomCryptoUtils.verify(pk, signature, message);
            
            if (!isValid) {
                Log.e(TAG, "Registration verification failed, invalid signature");
                return new VerificationResult(false, null, null);
            }

            ServerStorage.saveRcs(credentialId, pk, rs);
            
            Log.d(TAG, "Registration verification successful, saved public key and rs");
            return new VerificationResult(true, pk, null);
        } catch (Exception e) {
            Log.e(TAG, "Registration verification exception: " + e.getMessage());
            return new VerificationResult(false, null, null);
        }
    }
    
    @Override
    public ChallengeResult generateAuthenticationChallenge(byte[] credentialId, byte[] serverId) {
        byte[] rs = CustomCryptoUtils.generateRandomBytes(32);

        byte[] challenge = CustomCryptoUtils.concat(serverId, rs);
        byte[] state = Arrays.copyOf(challenge, challenge.length);
        
        Log.d(TAG, "Generated authentication challenge, server ID: " + ByteUtils.toHex(serverId));
        return new ChallengeResult(challenge, state);
    }
    
    @Override
    public CommitmentResult computeAuthenticationCommitment(byte[] serverId, byte[] credentialId, byte[] challenge) {

        byte[] id = Arrays.copyOf(challenge, serverId.length);

        if (!Arrays.equals(id, serverId)) {
            Log.e(TAG, "Server ID mismatch");
            throw new IllegalArgumentException("Server ID mismatch");
        }
        
        byte[] rs = Arrays.copyOfRange(challenge, serverId.length, challenge.length);

        byte[] ma = CustomCryptoUtils.H_0(rs);
        
        Log.d(TAG, "Computed authentication commitment, M_a: " + ByteUtils.toHex(ma));
        return new CommitmentResult(ma);
    }
    
    @Override
    public TokenResponseResult generateAuthenticationResponse(byte[] serverId, byte[] credentialId, byte[] commitment) {

        PrivateKey sk0 = tokenMasterKey.getSk0();
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] seed = tokenMasterKey.getSeed();
        
        try {
            byte[] decrypted = CustomCryptoUtils.Dec(seed, credentialId);

            int serverIdLength = 32;
            byte[] extractedId = Arrays.copyOf(decrypted, serverIdLength);
            byte[] r = Arrays.copyOfRange(decrypted, serverIdLength, decrypted.length);

            if (!Arrays.equals(extractedId, serverId)) {
                Log.e(TAG, "Server ID mismatch in credential");
                throw new IllegalArgumentException("Server ID mismatch in credential");
            }

            byte[] pkBytes = pk0.getEncoded();
            PrivateKey sk = KeyRandomizer.RandSK(sk0, derivationSeed);

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] ma = commitment; // M_a就是commitment
            byte[] message = CustomCryptoUtils.concat(idSHash, ma);

            byte[] coins = CustomCryptoUtils.H_1(seed, message);

            byte[] signature = CustomCryptoUtils.sign(sk, message, coins);

            Log.d(TAG, "Generated authentication response");
            return new TokenResponseResult(null, signature);
        } catch (Exception e) {
            Log.e(TAG, "Generate authentication response exception: " + e.getMessage());
            throw new RuntimeException("Failed to generate authentication response", e);
        }
    }
    
    @Override
    public boolean verifyAuthentication(byte[] state, byte[] credentialId, byte[] clientResponse) {
        try {

            int serverIdLength = 32;
            
            byte[] serverId = Arrays.copyOf(state, serverIdLength);
            byte[] rs = Arrays.copyOfRange(state, serverIdLength, state.length);

            ServerStorage.ServerContext context = ServerStorage.getRcs(credentialId);
            if (context == null) {
                Log.e(TAG, "No server context found for credential ID");
                return false;
            }
            
            PublicKey pk = context.getPk();

            byte[] ma = CustomCryptoUtils.H_0(rs);

            byte[] idSHash = CustomCryptoUtils.H_0(serverId);
            byte[] message = CustomCryptoUtils.concat(idSHash, ma);

            byte[] signature = clientResponse;
            boolean isValid = CustomCryptoUtils.verify(pk, signature, message);
            
            if (isValid) {
                Log.d(TAG, "Authentication verification successful");
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

        Log.d(TAG, "BIP32-SU scheme does not require client storage");
    }
    
    @Override
    public void clearStorage() {
        ClientStorage.clear();
        ServerStorage.clear();
        Log.d(TAG, "Cleared storage");
    }
    

    public byte[] generateRevocationKey() {
        PublicKey pk0 = tokenMasterKey.getPk0();
        byte[] ch = tokenMasterKey.getCh();
        byte[] lrev = tokenMasterKey.getLrev();

        byte[] pkBytes = pk0.getEncoded();
        byte[] revocationKey = CustomCryptoUtils.concat(pkBytes, 
                               CustomCryptoUtils.concat(ch, lrev));
        
        Log.d(TAG, "Generated revocation key");
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
            
            Log.d(TAG, "Check credential for revocation: " + needsRevocation);
            return needsRevocation;
        } catch (Exception e) {
            Log.e(TAG, "Check credential for revocation exception: " + e.getMessage());
            return false;
        }
    }
    

    private boolean isTerminalLrevValue(byte[] lrev) {
        if (lrev == null || lrev.length == 0) {
            return true;
        }
        
        for (byte b : lrev) {
            if (b != 0) {
                return false;
            }
        }
        
        return true;
    }
} 