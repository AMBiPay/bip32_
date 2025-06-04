package com.sample.authenticator.server;

import android.content.Context;
import android.util.Log;
import android.widget.Toast;

import com.sample.authenticator.server.param.ServerAssertionResultRequest;
import com.sample.authenticator.server.param.ServerAttestationResultRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsRequest;
import com.sample.authenticator.server.param.ServerPublicKeyCredentialCreationOptionsResponse;
import com.sample.authenticator.server.param.ServerRegDeleteRequest;
import com.sample.authenticator.server.param.ServerRegInfoRequest;
import com.sample.authenticator.server.param.ServerRegInfoResponse;
import com.sample.authenticator.server.param.ServerResponse;
import com.sample.authenticator.server.param.ServerStatus;
import com.sample.authenticator.server.protocol.FidoProtocolFactory;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;


public class PcServerSimulator {
    private static final String TAG = "PcServerSimulator";
    

    private static final int SERVER_PORT = 8080;
    

    private boolean isRunning = false;
    

    private final ExecutorService executorService = Executors.newCachedThreadPool();
    

    private ServerSocket serverSocket;
    

    private final Context context;
    

    private final FidoServerSimulator fidoServer;
    

    public PcServerSimulator(Context context) {
        this.context = context;
        this.fidoServer = new FidoServerSimulator();
    }
    

    public void start() {
        if (isRunning) {
            Log.w(TAG, "Server is already running");
            return;
        }
        
        executorService.execute(() -> {
            try {
                serverSocket = new ServerSocket(SERVER_PORT);
                isRunning = true;
                Log.i(TAG, "Server started, port: " + SERVER_PORT);
                
                if (context != null) {
                    Toast.makeText(context, "PC Server Simulator started, port: " + SERVER_PORT, Toast.LENGTH_SHORT).show();
                }
                
                while (isRunning) {
                    try {
                        Socket clientSocket = serverSocket.accept();
                        handleClient(clientSocket);
                    } catch (IOException e) {
                        if (isRunning) {
                            Log.e(TAG, "Error accepting client connection", e);
                        }
                    }
                }
            } catch (IOException e) {
                Log.e(TAG, "Error starting server", e);
                isRunning = false;
                
                if (context != null) {
                    Toast.makeText(context, "PC Server Simulator failed to start: " + e.getMessage(), Toast.LENGTH_SHORT).show();
                }
            }
        });
    }
    

    private void handleClient(Socket clientSocket) {
        executorService.execute(() -> {
            try {

                clientSocket.close();
            } catch (IOException e) {
                Log.e(TAG, "Error handling client connection", e);
            }
        });
    }
    

    public void stop() {
        if (!isRunning) {
            Log.w(TAG, "Server is not running");
            return;
        }
        
        isRunning = false;
        
        try {
            if (serverSocket != null) {
                serverSocket.close();
            }
        } catch (IOException e) {
            Log.e(TAG, "Error stopping server", e);
        }
        
        Log.i(TAG, "Server stopped");
        
        if (context != null) {
            Toast.makeText(context, "PC Server Simulator stopped", Toast.LENGTH_SHORT).show();
        }
    }
    

    public String getCurrentScheme() {
        return FidoProtocolFactory.getInstance().getCurrentScheme().getSchemeName();
    }
} 