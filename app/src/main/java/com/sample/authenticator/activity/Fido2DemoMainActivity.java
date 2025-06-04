package com.sample.authenticator.activity;

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
import com.sample.authenticator.server.ByteUtils;
import com.sample.authenticator.server.CustomCryptoUtils;
import com.sample.authenticator.server.FidoServerFactory;
import com.sample.authenticator.server.IFidoServer;
import com.sample.authenticator.server.protocol.FidoProtocolFactory;
import com.sample.authenticator.server.protocol.FidoProtocolScheme;
public class Fido2DemoMainActivity extends AppCompatActivity {

    private TextView tvCurrentScheme;
    private Button btnScheme1;
    private Button btnScheme2;
    private Button btnScheme3;
    private Button btnScheme4;
    private Button btnScheme5;
    private Button btnScheme6;
    private Button btnRegister;
    private Button btnAuthenticate;
    private Button btnTestPerformance;

    private IFidoServer fidoServer;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_fido2_demo_main);

        FidoServerFactory.init(this);
        fidoServer = initFidoServer();

        initProtocolFactory();

        initViews();

        setupListeners();

        updateCurrentSchemeDisplay();
    }
    private IFidoServer initFidoServer() {
        return FidoServerFactory.createServer();
    }
    private void initProtocolFactory() {
        FidoProtocolFactory protocolFactory = FidoProtocolFactory.getInstance();
    }
    private void initViews() {
        tvCurrentScheme = findViewById(R.id.tv_current_scheme);
        btnScheme1 = findViewById(R.id.btn_scheme1);
        btnScheme2 = findViewById(R.id.btn_scheme2);
        btnScheme3 = findViewById(R.id.btn_scheme3);
        btnScheme4 = findViewById(R.id.btn_scheme4);
        btnScheme5 = findViewById(R.id.btn_scheme5);
        btnScheme6 = findViewById(R.id.btn_scheme6);
        btnRegister = findViewById(R.id.btn_register);
        btnAuthenticate = findViewById(R.id.btn_authenticate);
        btnTestPerformance = findViewById(R.id.btn_test_performance);
    }
    private void setupListeners() {
        btnScheme1.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(0);
            updateCurrentSchemeDisplay();
        });
        
        btnScheme2.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(1);
            updateCurrentSchemeDisplay();
        });
        
        btnScheme3.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(2);
            updateCurrentSchemeDisplay();
        });
        
        btnScheme4.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(3);
            updateCurrentSchemeDisplay();
        });
        
        btnScheme5.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(4);
            updateCurrentSchemeDisplay();
        });
        
        btnScheme6.setOnClickListener(v -> {
            FidoProtocolFactory.getInstance().setCurrentScheme(5);
            updateCurrentSchemeDisplay();
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
                } else {
                    Toast.makeText(this, "Authentication failed", Toast.LENGTH_SHORT).show();
                }
            } catch (Exception e) {
                Toast.makeText(this, "Authentication exception: " + e.getMessage(), Toast.LENGTH_SHORT).show();
            }
        });

        btnTestPerformance.setOnClickListener(v -> {
            Intent intent = new Intent(this, PerformanceTestActivity.class);
            startActivity(intent);
        });
    }

    private void updateCurrentSchemeDisplay() {
        FidoProtocolFactory protocolFactory = FidoProtocolFactory.getInstance();
        String schemeName = protocolFactory.getCurrentScheme().getSchemeName();
        tvCurrentScheme.setText("Current Scheme: " + schemeName);
    }

    @Override
    protected void onResume() {
        super.onResume();
        fidoServer = initFidoServer();
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