package com.sample.authenticator.server.protocol;

import java.security.PublicKey;


public interface FidoProtocolScheme {

    String getSchemeName();

    

    ChallengeResult generateRegistrationChallenge(byte[] serverId);
    

    CommitmentResult computeRegistrationCommitment(byte[] serverId, byte[] challenge);
    

    TokenResponseResult generateRegistrationResponse(byte[] serverId, byte[] commitment);
    

    DecapResult processRegistrationTokenResponse(byte[] credentialId, byte[] tokenResponse);
    

    VerificationResult verifyRegistration(byte[] state, byte[] credentialId, byte[] clientResponse);
    

    ChallengeResult generateAuthenticationChallenge(byte[] credentialId, byte[] serverId);
    

    CommitmentResult computeAuthenticationCommitment(byte[] serverId, byte[] credentialId, byte[] challenge);
    

    TokenResponseResult generateAuthenticationResponse(byte[] serverId, byte[] credentialId, byte[] commitment);
    

    boolean verifyAuthentication(byte[] state, byte[] credentialId, byte[] clientResponse);
    

    default void updateClientStorage(byte[] credentialId, byte[] newData) {
    }
    

    void clearStorage();

    class ChallengeResult {
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
    

    class CommitmentResult {
        private final byte[] commitment;
        
        public CommitmentResult(byte[] commitment) {
            this.commitment = commitment;
        }
        
        public byte[] getCommitment() {
            return commitment;
        }
    }
    

    class TokenResponseResult {
        private final byte[] credentialId;
        private final byte[] tokenResponse;
        
        public TokenResponseResult(byte[] credentialId, byte[] tokenResponse) {
            this.credentialId = credentialId;
            this.tokenResponse = tokenResponse;
        }
        
        public byte[] getCredentialId() {
            return credentialId;
        }
        
        public byte[] getTokenResponse() {
            return tokenResponse;
        }
    }
    

    class DecapResult {
        private final byte[] response;
        private final byte[] clientStorage;
        
        public DecapResult(byte[] response, byte[] clientStorage) {
            this.response = response;
            this.clientStorage = clientStorage;
        }
        
        public byte[] getResponse() {
            return response;
        }
        
        public byte[] getClientStorage() {
            return clientStorage;
        }
    }

    class VerificationResult {
        private final boolean success;
        private final PublicKey publicKey;
        private final byte[] extraData;
        
        public VerificationResult(boolean success, PublicKey publicKey, byte[] extraData) {
            this.success = success;
            this.publicKey = publicKey;
            this.extraData = extraData;
        }
        
        public boolean isSuccess() {
            return success;
        }
        
        public PublicKey getPublicKey() {
            return publicKey;
        }
        
        public byte[] getExtraData() {
            return extraData;
        }
    }
} 