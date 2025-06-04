package com.sample.authenticator.server;

import android.util.Log;

import com.google.gson.Gson;
import com.sample.authenticator.server.param.ServerAssertionResultRequest;
import com.sample.authenticator.server.param.ServerAttestationResultRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsResponse;
import com.sample.authenticator.server.param.ServerRegDeleteRequest;
import com.sample.authenticator.server.param.ServerRegInfoRequest;
import com.sample.authenticator.server.param.ServerRegInfoResponse;
import com.sample.authenticator.server.param.ServerResponse;
import com.sample.authenticator.server.param.ServerStatus;

import java.io.IOException;
import java.util.concurrent.TimeUnit;

import okhttp3.MediaType;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;


public class PcFidoServer implements IFidoServer {
    private static final String TAG = "PcFidoServer";
    

    private static final MediaType JSON = MediaType.parse("application/json; charset=utf-8");
    

    private final String serverAddress;
    

    private final OkHttpClient client;
    

    private final Gson gson;
    

    public PcFidoServer(String serverAddress) {
        this.serverAddress = serverAddress;
        

        this.client = new OkHttpClient.Builder()
                .connectTimeout(30, TimeUnit.SECONDS)
                .readTimeout(30, TimeUnit.SECONDS)
                .writeTimeout(30, TimeUnit.SECONDS)
                .build();
        

        this.gson = new Gson();
    }
    
    @Override
    public ServerPublicKeyCredentialCreationOptionsResponse getAttestationOptions(
            ServerPublicKeyCredentialCreationOptionsRequest request) {
        try {

            String json = gson.toJson(request);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/attestation/options")
                    .post(body)
                    .build();
            

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "Failed to obtain the registration options.\n: " + response.code());
                ServerPublicKeyCredentialCreationOptionsResponse errorResponse = 
                        new ServerPublicKeyCredentialCreationOptionsResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("Failed to obtain the registration options.\n: " + response.code());
                return errorResponse;
            }

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerPublicKeyCredentialCreationOptionsResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while obtaining the registration options.", e);
            ServerPublicKeyCredentialCreationOptionsResponse errorResponse = 
                    new ServerPublicKeyCredentialCreationOptionsResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while obtaining the registration options.: " + e.getMessage());
            return errorResponse;
        }
    }
    
    @Override
    public ServerResponse getAttestationResult(ServerAttestationResultRequest attestationResultRequest) {
        try {

            String json = gson.toJson(attestationResultRequest);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/attestation/result")
                    .post(body)
                    .build();
            

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "ailed to obtain the registration options: " + response.code());
                ServerResponse errorResponse = new ServerResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("ailed to obtain the registration options: " + response.code());
                return errorResponse;
            }
            

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while obtaining the registration options", e);
            ServerResponse errorResponse = new ServerResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while obtaining the registration options: " + e.getMessage());
            return errorResponse;
        }
    }
    
    @Override
    public ServerPublicKeyCredentialCreationOptionsResponse getAssertionOptions(
            ServerPublicKeyCredentialCreationOptionsRequest request) {
        try {

            String json = gson.toJson(request);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/assertion/options")
                    .post(body)
                    .build();
            

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "Failed to obtain the authentication options.\n: " + response.code());
                ServerPublicKeyCredentialCreationOptionsResponse errorResponse = 
                        new ServerPublicKeyCredentialCreationOptionsResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("Failed to obtain the authentication options.\n: " + response.code());
                return errorResponse;
            }
            

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerPublicKeyCredentialCreationOptionsResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while obtaining the authentication options.\n", e);
            ServerPublicKeyCredentialCreationOptionsResponse errorResponse = 
                    new ServerPublicKeyCredentialCreationOptionsResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while obtaining the authentication options.\n: " + e.getMessage());
            return errorResponse;
        }
    }
    
    @Override
    public ServerResponse getAssertionResult(ServerAssertionResultRequest assertionResultRequest) {
        try {

            String json = gson.toJson(assertionResultRequest);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/assertion/result")
                    .post(body)
                    .build();
            

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "Failed to obtain the authentication result.\n: " + response.code());
                ServerResponse errorResponse = new ServerResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("Failed to obtain the authentication result.\n: " + response.code());
                return errorResponse;
            }

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while obtaining the authentication result", e);
            ServerResponse errorResponse = new ServerResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while obtaining the authentication result: " + e.getMessage());
            return errorResponse;
        }
    }
    
    @Override
    public ServerRegInfoResponse getRegInfo(ServerRegInfoRequest regInfoRequest) {
        try {

            String json = gson.toJson(regInfoRequest);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/reginfo")
                    .post(body)
                    .build();
            

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "Failed to obtain the registration information.\n: " + response.code());
                ServerRegInfoResponse errorResponse = new ServerRegInfoResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("Failed to obtain the registration information.\n: " + response.code());
                return errorResponse;
            }
            

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerRegInfoResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while obtaining the registration information", e);
            ServerRegInfoResponse errorResponse = new ServerRegInfoResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while obtaining the registration information: " + e.getMessage());
            return errorResponse;
        }
    }
    
    @Override
    public ServerResponse delete(ServerRegDeleteRequest regDeleteRequest) {
        try {

            String json = gson.toJson(regDeleteRequest);
            

            RequestBody body = RequestBody.create(json, JSON);
            Request httpRequest = new Request.Builder()
                    .url(serverAddress + "/delete")
                    .post(body)
                    .build();

            Response response = client.newCall(httpRequest).execute();
            

            if (!response.isSuccessful()) {
                Log.e(TAG, "Failed to delete the registration information.\n: " + response.code());
                ServerResponse errorResponse = new ServerResponse();
                errorResponse.setStatus(ServerStatus.FAILED.getCode());
                errorResponse.setErrorMessage("Failed to delete the registration information.\n: " + response.code());
                return errorResponse;
            }
            

            String responseBody = response.body().string();
            return gson.fromJson(responseBody, ServerResponse.class);
        } catch (IOException e) {
            Log.e(TAG, "An exception occurred while deleting the registration information.", e);
            ServerResponse errorResponse = new ServerResponse();
            errorResponse.setStatus(ServerStatus.FAILED.getCode());
            errorResponse.setErrorMessage("An exception occurred while deleting the registration information.: " + e.getMessage());
            return errorResponse;
        }
    }
} 