package com.sample.authenticator.server;

import android.os.Debug;
import android.util.Log;

import com.sample.authenticator.server.protocol.FidoProtocolScheme;

import java.util.ArrayList;
import java.util.List;


public class PerformanceTest {
    private static final String TAG = "PerformanceTest";

    private static final Runtime runtime = Runtime.getRuntime();


    public static long testComputationOverhead(String name, Runnable action) {

        System.gc();
        
        long startTime = System.currentTimeMillis();
        

        action.run();
        
        long endTime = System.currentTimeMillis();
        long executionTime = endTime - startTime;
        
        Log.d(TAG, "Calculate the overhead [" + name + "]: " + executionTime + " ms");
        return executionTime;
    }
    

    public static long testStorageOverhead(String name, Runnable action) {

        System.gc();
        

        long initialMemory = getUsedMemory();
        

        action.run();
        

        long finalMemory = getUsedMemory();
        
        long memoryUsed = finalMemory - initialMemory;
        Log.d(TAG, "Storage overhead\n [" + name + "]: " + memoryUsed + " bytes");
        return memoryUsed;
    }
    

    private static long getUsedMemory() {
        return runtime.totalMemory() - runtime.freeMemory();
    }
    

    public static TestResult testComputationOverhead(FidoProtocolScheme scheme, int iterations) {

        scheme.clearStorage();
        

        byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);
        byte[] credentialId = null;
        

        List<Long> registrationTimes = new ArrayList<>();
        

        for (int i = 0; i < iterations; i++) {
            long startTime = System.currentTimeMillis();
            

            FidoProtocolScheme.ChallengeResult challengeResult = scheme.generateRegistrationChallenge(serverId);
            byte[] challenge = challengeResult.getChallenge();
            byte[] state = challengeResult.getState();
            

            FidoProtocolScheme.CommitmentResult commitmentResult = scheme.computeRegistrationCommitment(serverId, challenge);
            byte[] commitment = commitmentResult.getCommitment();
            

            FidoProtocolScheme.TokenResponseResult tokenResponseResult = scheme.generateRegistrationResponse(serverId, commitment);
            credentialId = tokenResponseResult.getCredentialId();
            byte[] tokenResponse = tokenResponseResult.getResponse();
            

            FidoProtocolScheme.DecapResult decapResult = scheme.processRegistrationTokenResponse(credentialId, tokenResponse);
            byte[] clientResponse = decapResult.getClientResponse();
            

            FidoProtocolScheme.VerificationResult verificationResult = scheme.verifyRegistration(state, credentialId, clientResponse);
            
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            registrationTimes.add(duration);
        }
        

        List<Long> authenticationTimes = new ArrayList<>();
        

        for (int i = 0; i < iterations; i++) {
            long startTime = System.currentTimeMillis();
            

            FidoProtocolScheme.ChallengeResult challengeResult = scheme.generateAuthenticationChallenge(credentialId, serverId);
            byte[] challenge = challengeResult.getChallenge();
            byte[] state = challengeResult.getState();
            

            FidoProtocolScheme.CommitmentResult commitmentResult = scheme.computeAuthenticationCommitment(serverId, credentialId, challenge);
            byte[] commitment = commitmentResult.getCommitment();
            

            FidoProtocolScheme.TokenResponseResult tokenResponseResult = scheme.generateAuthenticationResponse(serverId, credentialId, commitment);
            byte[] tokenResponse = tokenResponseResult.getResponse();
            

            boolean isValid = scheme.verifyAuthentication(state, credentialId, tokenResponse);
            
            long endTime = System.currentTimeMillis();
            long duration = endTime - startTime;
            authenticationTimes.add(duration);
        }
        

        long totalRegistrationTime = 0;
        long minRegistrationTime = Long.MAX_VALUE;
        long maxRegistrationTime = 0;
        
        for (long time : registrationTimes) {
            totalRegistrationTime += time;
            minRegistrationTime = Math.min(minRegistrationTime, time);
            maxRegistrationTime = Math.max(maxRegistrationTime, time);
        }
        
        double avgRegistrationTime = (double) totalRegistrationTime / iterations;
        

        long totalAuthenticationTime = 0;
        long minAuthenticationTime = Long.MAX_VALUE;
        long maxAuthenticationTime = 0;
        
        for (long time : authenticationTimes) {
            totalAuthenticationTime += time;
            minAuthenticationTime = Math.min(minAuthenticationTime, time);
            maxAuthenticationTime = Math.max(maxAuthenticationTime, time);
        }
        
        double avgAuthenticationTime = (double) totalAuthenticationTime / iterations;
        
        Log.d(TAG, "Calculate the performance test results. [" + scheme.getSchemeName() + "]:");
        Log.d(TAG, "Registration phase - Average: " + avgRegistrationTime + " ms, minimum: " + minRegistrationTime + " ms, maximum: " + maxRegistrationTime + " ms");
        Log.d(TAG, "Authentication phase - Average: " + avgAuthenticationTime + " ms, minimum: " + minAuthenticationTime + " ms, maximum: " + maxAuthenticationTime + " ms");
        
        return new TestResult(scheme.getSchemeName(), 
                              avgRegistrationTime, minRegistrationTime, maxRegistrationTime,
                              avgAuthenticationTime, minAuthenticationTime, maxAuthenticationTime,
                              0, 0, 0);
    }
    

    public static TestResult testStorageOverhead(FidoProtocolScheme scheme, int iterations) {

        scheme.clearStorage();
        

        byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);
        

        System.gc();
        

        long initialMemory = getUsedMemory();
        

        for (int i = 0; i < iterations; i++) {

            FidoProtocolScheme.ChallengeResult challengeResult = scheme.generateRegistrationChallenge(serverId);
            byte[] challenge = challengeResult.getChallenge();
            byte[] state = challengeResult.getState();
            

            FidoProtocolScheme.CommitmentResult commitmentResult = scheme.computeRegistrationCommitment(serverId, challenge);
            byte[] commitment = commitmentResult.getCommitment();
            

            FidoProtocolScheme.TokenResponseResult tokenResponseResult = scheme.generateRegistrationResponse(serverId, commitment);
            byte[] credentialId = tokenResponseResult.getCredentialId();
            byte[] tokenResponse = tokenResponseResult.getResponse();
            

            FidoProtocolScheme.DecapResult decapResult = scheme.processRegistrationTokenResponse(credentialId, tokenResponse);
            byte[] clientResponse = decapResult.getClientResponse();
            

            FidoProtocolScheme.VerificationResult verificationResult = scheme.verifyRegistration(state, credentialId, clientResponse);
        }
        

        System.gc();
        

        long serverStorageBytes = ServerStorage.getStorageSize();

        long clientStorageBytes = ClientStorage.getStorageSize();
        

        long totalStorageBytes = serverStorageBytes + clientStorageBytes;
        

        long avgServerStorageBytes = iterations > 0 ? serverStorageBytes / iterations : 0;
        long avgClientStorageBytes = iterations > 0 ? clientStorageBytes / iterations : 0;
        long avgTotalStorageBytes = iterations > 0 ? totalStorageBytes / iterations : 0;
        
        Log.d(TAG, "Storage performance test results [" + scheme.getSchemeName() + "]:");
        Log.d(TAG, "Server storage overhead: " + serverStorageBytes + " bytes (" + avgServerStorageBytes + " bytes/credential)");
        Log.d(TAG, "Client - side storage overhead: " + clientStorageBytes + " bytes (" + avgClientStorageBytes + " bytes/credential)");
        Log.d(TAG, "Total storage overhead: " + totalStorageBytes + " bytes (" + avgTotalStorageBytes + " bytes/credential)");
        
        return new TestResult(scheme.getSchemeName(), 
                              0, 0, 0,
                              0, 0, 0,
                              clientStorageBytes, serverStorageBytes, totalStorageBytes);
    }

    public static class TestResult {
        private final String schemeName;
        

        private final double avgRegistrationTime;
        private final long minRegistrationTime;
        private final long maxRegistrationTime;
        
        private final double avgAuthenticationTime;
        private final long minAuthenticationTime;
        private final long maxAuthenticationTime;
        

        private final long clientStorageBytes;
        private final long serverStorageBytes;
        private final long totalStorageBytes;
        
        public TestResult(String schemeName, 
                          double avgRegistrationTime, long minRegistrationTime, long maxRegistrationTime,
                          double avgAuthenticationTime, long minAuthenticationTime, long maxAuthenticationTime,
                          long clientStorageBytes, long serverStorageBytes, long totalStorageBytes) {
            this.schemeName = schemeName;
            this.avgRegistrationTime = avgRegistrationTime;
            this.minRegistrationTime = minRegistrationTime;
            this.maxRegistrationTime = maxRegistrationTime;
            this.avgAuthenticationTime = avgAuthenticationTime;
            this.minAuthenticationTime = minAuthenticationTime;
            this.maxAuthenticationTime = maxAuthenticationTime;
            this.clientStorageBytes = clientStorageBytes;
            this.serverStorageBytes = serverStorageBytes;
            this.totalStorageBytes = totalStorageBytes;
        }
        
        public String getSchemeName() {
            return schemeName;
        }
        
        public double getAvgRegistrationTime() {
            return avgRegistrationTime;
        }
        
        public long getMinRegistrationTime() {
            return minRegistrationTime;
        }
        
        public long getMaxRegistrationTime() {
            return maxRegistrationTime;
        }
        
        public double getAvgAuthenticationTime() {
            return avgAuthenticationTime;
        }
        
        public long getMinAuthenticationTime() {
            return minAuthenticationTime;
        }
        
        public long getMaxAuthenticationTime() {
            return maxAuthenticationTime;
        }
        
        public long getClientStorageBytes() {
            return clientStorageBytes;
        }
        
        public long getServerStorageBytes() {
            return serverStorageBytes;
        }
        
        public long getTotalStorageBytes() {
            return totalStorageBytes;
        }
        
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("方案 [").append(schemeName).append("]").append("\n");
            
            if (avgRegistrationTime > 0 || avgAuthenticationTime > 0) {
                sb.append("Computational performance:\n");
                sb.append("  Registration: Average =").append(avgRegistrationTime).append("ms, minimum=").append(minRegistrationTime).append("ms, maximum=").append(maxRegistrationTime).append("ms\n");
                sb.append("  Authentication: Average =").append(avgAuthenticationTime).append("ms, minimum=").append(minAuthenticationTime).append("ms, maximum=").append(maxAuthenticationTime).append("ms\n");
            }
            
            if (clientStorageBytes > 0 || serverStorageBytes > 0) {
                sb.append("Storage overhead:\n");
                sb.append("  Client: ").append(clientStorageBytes).append(" bytes\n");
                sb.append("  Sever: ").append(serverStorageBytes).append(" bytes\n");
                sb.append("  In total: ").append(totalStorageBytes).append(" bytes\n");
            }
            
            return sb.toString();
        }
    }
} 