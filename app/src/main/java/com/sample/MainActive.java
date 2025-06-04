package com.sample;

import android.content.Intent;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.Button;
import android.widget.TextView;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.sample.authenticator.R;
import com.sample.authenticator.activity.Fido2DemoMainActivity;
import com.sample.authenticator.activity.PerformanceTestActivity;
import com.sample.authenticator.activity.SettingsActivity;
import com.sample.authenticator.server.ByteUtils;
import com.sample.authenticator.server.FidoServerFactory;
import com.sample.authenticator.server.IFidoServer;
import com.sample.authenticator.server.protocol.FidoProtocolFactory;
import com.sample.authenticator.server.protocol.FidoProtocolScheme;
import com.sample.authenticator.server.CustomCryptoUtils;

public class MainActive extends AppCompatActivity {

    private TextView tvStatus;
    private Button btnStartTest;
    private Button btnRegister;
    private Button btnAuthenticate;
    private Button btnPerformanceTest;
    private Button btnSettings;
    
    private IFidoServer fidoServer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        
        FidoServerFactory.init(this);
        fidoServer = initFidoServer();
        
        initProtocolFactory();
        
        initViews();
        
        setupListeners();
        
        updateStatusDisplay();
    }
    
    private IFidoServer initFidoServer() {
        return FidoServerFactory.createServer();
    }
    
    private void initProtocolFactory() {
        FidoProtocolFactory protocolFactory = FidoProtocolFactory.getInstance();
    }
    
    private void initViews() {
        tvStatus = findViewById(R.id.tv_status);
        btnStartTest = findViewById(R.id.btn_start_test);
        btnRegister = findViewById(R.id.btn_register);
        btnAuthenticate = findViewById(R.id.btn_authenticate);
        btnPerformanceTest = findViewById(R.id.btn_performance_test);
        btnSettings = findViewById(R.id.btn_settings);
    }
    
    private void setupListeners() {
        btnStartTest.setOnClickListener(v -> {
            Intent intent = new Intent(this, Fido2DemoMainActivity.class);
            startActivity(intent);
        });
        
        btnRegister.setOnClickListener(v -> {
            try {
                FidoProtocolScheme scheme = FidoProtocolFactory.getInstance().getCurrentScheme();
                
                byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);
                
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
                
                if (verificationResult.isSuccess()) {
                    Toast.makeText(this, "Registration successful! Credential ID: " + ByteUtils.toHex(credentialId).substring(0, 16) + "...", Toast.LENGTH_SHORT).show();
                    updateStatusDisplay();
                } else {
                    Toast.makeText(this, "Registration failed", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                Toast.makeText(this, "Registration exception: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });
        
        btnAuthenticate.setOnClickListener(v -> {
            try {
                FidoProtocolScheme scheme = FidoProtocolFactory.getInstance().getCurrentScheme();
                
                byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);
                
                FidoProtocolScheme.ChallengeResult regChallengeResult = scheme.generateRegistrationChallenge(serverId);
                FidoProtocolScheme.CommitmentResult regCommitmentResult = scheme.computeRegistrationCommitment(serverId, regChallengeResult.getChallenge());
                FidoProtocolScheme.TokenResponseResult regTokenResponseResult = scheme.generateRegistrationResponse(serverId, regCommitmentResult.getCommitment());
                byte[] credentialId = regTokenResponseResult.getCredentialId();
                FidoProtocolScheme.DecapResult regDecapResult = scheme.processRegistrationTokenResponse(credentialId, regTokenResponseResult.getResponse());
                FidoProtocolScheme.VerificationResult regVerificationResult = scheme.verifyRegistration(regChallengeResult.getState(), credentialId, regDecapResult.getClientResponse());
                
                if (!regVerificationResult.isSuccess()) {
                    Toast.makeText(this, "Registration before authentication failed", Toast.LENGTH_SHORT).show();
                    return;
                }
                
                FidoProtocolScheme.ChallengeResult challengeResult = scheme.generateAuthenticationChallenge(credentialId, serverId);
                byte[] challenge = challengeResult.getChallenge();
                byte[] state = challengeResult.getState();
                
                FidoProtocolScheme.CommitmentResult commitmentResult = scheme.computeAuthenticationCommitment(serverId, credentialId, challenge);
                byte[] commitment = commitmentResult.getCommitment();
                
                FidoProtocolScheme.TokenResponseResult tokenResponseResult = scheme.generateAuthenticationResponse(serverId, credentialId, commitment);
                byte[] tokenResponse = tokenResponseResult.getResponse();
                
                boolean isValid = scheme.verifyAuthentication(state, credentialId, tokenResponse);
                
                if (isValid) {
                    Toast.makeText(this, "Authentication successful!", Toast.LENGTH_SHORT).show();
                    updateStatusDisplay();
                } else {
                    Toast.makeText(this, "Authentication failed", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                Toast.makeText(this, "Authentication exception: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });
        
        btnPerformanceTest.setOnClickListener(v -> {
            Intent intent = new Intent(this, PerformanceTestActivity.class);
            startActivity(intent);
        });
        
        btnSettings.setOnClickListener(v -> {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
        });
    }
    
    private void updateStatusDisplay() {
        FidoProtocolFactory protocolFactory = FidoProtocolFactory.getInstance();
        String schemeName = protocolFactory.getCurrentScheme().getSchemeName();
        tvStatus.setText("Current Scheme: " + schemeName);
    }
    
    @Override
    protected void onResume() {
        super.onResume();
        fidoServer = initFidoServer();
        updateStatusDisplay();
    }
    
    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        getMenuInflater().inflate(R.menu.main_menu, menu);
        return true;
    }
    
    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        int id = item.getItemId();
        if (id == R.id.action_settings) {
            Intent intent = new Intent(this, SettingsActivity.class);
            startActivity(intent);
            return true;
        }
        return super.onOptionsItemSelected(item);
    }
} 