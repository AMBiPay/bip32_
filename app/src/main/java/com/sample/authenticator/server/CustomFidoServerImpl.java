package com.sample.authenticator.server;

import android.util.Log;

import com.sample.authenticator.server.param.ServerAssertionResultRequest;
import com.sample.authenticator.server.param.ServerAttestationResultRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsResponse;
import com.sample.authenticator.server.param.ServerRegDeleteRequest;
import com.sample.authenticator.server.param.ServerRegInfo;
import com.sample.authenticator.server.param.ServerRegInfoRequest;
import com.sample.authenticator.server.param.ServerRegInfoResponse;
import com.sample.authenticator.server.param.ServerResponse;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class CustomFidoServerImpl implements IFidoServer {
    private static final String TAG = "CustomFidoServerImpl";
    

    private final byte[] serverId;
    

    private final Map<String, byte[]> serverStates = new HashMap<>();
    

    private final List<RegisteredCredential> registeredCredentials = new ArrayList<>();
    

    private static class RegisteredCredential {
        private final String credentialId;
        private PublicKey publicKey;
        
        public RegisteredCredential(String credentialId, PublicKey publicKey) {
            this.credentialId = credentialId;
            this.publicKey = publicKey;
        }
        
        public String getCredentialId() {
            return credentialId;
        }
        
        public PublicKey getPublicKey() {
            return publicKey;
        }
        
        public void setPublicKey(PublicKey publicKey) {
            this.publicKey = publicKey;
        }
    }
    

    public CustomFidoServerImpl() {

        this.serverId = "www.huawei.fidodemo".getBytes();
    }
    
    @Override
    public ServerPublicKeyCredentialCreationOptionsResponse getAttestationOptions(
            ServerPublicKeyCredentialCreationOptionsRequest request) {
        Log.d(TAG, "The registration challenge is being generated");
        

        CustomFidoProtocol.ChallengeResult challengeResult = 
                CustomFidoProtocol.rchall(serverId);
        

        String sessionId = ByteUtils.byte2base64(CustomCryptoUtils.generateRandomBytes(16));
        serverStates.put(sessionId, challengeResult.getState());
        

        ServerPublicKeyCredentialCreationOptionsResponse response = 
                new ServerPublicKeyCredentialCreationOptionsResponse();
        

        response.setChallenge(ByteUtils.byte2base64(challengeResult.getChallenge()));
        

        response.setRpId("www.huawei.fidodemo");
        

        response.setTimeout(60L);
        

        com.sample.authenticator.server.param.ServerPublicKeyCredentialUserEntity user =
                new com.sample.authenticator.server.param.ServerPublicKeyCredentialUserEntity();
        user.setId(request.getUsername());
        user.setDisplayName(request.getDisplayName());
        response.setUser(user);
        

        response.setSessionId(sessionId);
        
        return response;
    }
    
    @Override
    public ServerResponse getAttestationResult(ServerAttestationResultRequest request) {
        Log.d(TAG, "The registration result is being processed");
        
        try {

            String sessionId = request.getSessionId();
            String credentialId = request.getId();
            

            byte[] serverState = serverStates.get(sessionId);
            if (serverState == null) {
                return createErrorResponse("The session status was not found.");
            }
            

            byte[] clientResponse = ByteUtils.base642Byte(request.getResponse().getClientDataJSON());
            

            byte[] mHatR = clientResponse;
            

            CustomFidoProtocol.ResponseResult responseResult = 
                    CustomFidoProtocol.rresp(serverId, mHatR);
            

            byte[] cid = responseResult.getCid();
            byte[] rHatR = responseResult.getRHatR();
            
            CustomFidoProtocol.DecapResult decapResult = 
                    CustomFidoProtocol.rdecap(cid, rHatR);
            

            byte[] rR = decapResult.getRR();
            
            CustomFidoProtocol.CheckResult checkResult = 
                    CustomFidoProtocol.rcheck(serverState, cid, rR);
            
            if (!checkResult.isSuccess()) {
                return createErrorResponse("The registration verification failed");
            }
            

            RegisteredCredential credential = 
                    new RegisteredCredential(credentialId, checkResult.getPk());
            registeredCredentials.add(credential);
            

            serverStates.remove(sessionId);

            ServerResponse response = new ServerResponse();
            response.setStatus(ServerStatus.OK.getCode());
            response.setErrorMessage("");
            
            return response;
            
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred during the registration processing.\n", e);
            return createErrorResponse("注册过程出现错误: " + e.getMessage());
        }
    }
    
    @Override
    public ServerPublicKeyCredentialCreationOptionsResponse getAssertionOptions(
            ServerPublicKeyCredentialCreationOptionsRequest request) {
        Log.d(TAG, "The authentication challenge is being generated.\n");
        
        try {

            String credentialIdStr = request.getCredentialId();
            byte[] cid = ByteUtils.base642Byte(credentialIdStr);
            

            CustomFidoProtocol.AuthChallengeResult challengeResult = 
                    CustomFidoProtocol.achall(cid, serverId);
            

            String sessionId = ByteUtils.byte2base64(CustomCryptoUtils.generateRandomBytes(16));
            serverStates.put(sessionId, challengeResult.getState());
            

            ServerPublicKeyCredentialCreationOptionsResponse response = 
                    new ServerPublicKeyCredentialCreationOptionsResponse();
            

            response.setChallenge(ByteUtils.byte2base64(challengeResult.getChallenge()));
            

            response.setRpId("www.huawei.fidodemo");
            

            response.setTimeout(60L);
            

            response.setSessionId(sessionId);
            

            response.setCredentialId(credentialIdStr);
            
            return response;
            
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred while generating the authentication challenge.\n", e);
            ServerPublicKeyCredentialCreationOptionsResponse response = 
                    new ServerPublicKeyCredentialCreationOptionsResponse();
            response.setStatus(ServerStatus.FAILED.getCode());
            response.setErrorMessage("Failed to generate the authentication challenge.\n: " + e.getMessage());
            return response;
        }
    }
    
    @Override
    public ServerResponse getAssertionResult(ServerAssertionResultRequest request) {
        Log.d(TAG, "The authentication result is being processed.\n");
        
        try {

            String sessionId = request.getSessionId();
            String credentialId = request.getId();
            byte[] cid = ByteUtils.base642Byte(credentialId);
            

            byte[] serverState = serverStates.get(sessionId);
            if (serverState == null) {
                return createErrorResponse("The session status was not found.\n");
            }
            

            byte[] clientResponse = ByteUtils.base642Byte(request.getResponse().getClientDataJSON());
            

            byte[] mHatA = clientResponse;
            

            CustomFidoProtocol.AuthCommitResult commitResult = 
                    CustomFidoProtocol.acomm(serverId, cid, ByteUtils.base642Byte(request.getResponse().getAuthenticatorData()));
            

            CustomFidoProtocol.AuthResponseResult responseResult = 
                    CustomFidoProtocol.aresp(serverId, cid, commitResult.getMHatA());
            
            if (responseResult == null) {
                return createErrorResponse("The token authentication processing failed.");
            }
            

            boolean verified = CustomFidoProtocol.acheck(serverState, cid, responseResult.getRA());
            
            if (!verified) {
                return createErrorResponse("The authentication verification failed");
            }
            

            CustomFidoProtocol.updateClientStorage(cid, responseResult.getRHatA());
            

            serverStates.remove(sessionId);
            

            ServerResponse response = new ServerResponse();
            response.setStatus(ServerStatus.OK.getCode());
            response.setErrorMessage("");
            
            return response;
            
        } catch (Exception e) {
            Log.e(TAG, "An exception occurred during the authentication processing.\n", e);
            return createErrorResponse("An error occurred during the authentication process.\n误: " + e.getMessage());
        }
    }
    
    @Override
    public ServerRegInfoResponse getRegInfo(ServerRegInfoRequest regInfoRequest) {
        Log.d(TAG, "The registration information is being retrieved.");
        
        ServerRegInfoResponse response = new ServerRegInfoResponse();
        List<ServerRegInfo> infos = new ArrayList<>();
        
        for (RegisteredCredential credential : registeredCredentials) {
            ServerRegInfo info = new ServerRegInfo();
            info.setCredentialId(credential.getCredentialId());
            infos.add(info);
        }
        
        response.setInfos(infos);
        response.setStatus(ServerStatus.OK.getCode());
        
        return response;
    }
    
    @Override
    public ServerResponse delete(ServerRegDeleteRequest regDeleteRequest) {
        Log.d(TAG, "The registration information is being deleted");
        
        registeredCredentials.clear();
        serverStates.clear();
        
        ServerResponse response = new ServerResponse();
        response.setStatus(ServerStatus.OK.getCode());
        
        return response;
    }


    private ServerResponse createErrorResponse(String errorMessage) {
        ServerResponse response = new ServerResponse();
        response.setStatus(ServerStatus.FAILED.getCode());
        response.setErrorMessage(errorMessage);
        return response;
    }
} 