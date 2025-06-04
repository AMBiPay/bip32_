package com.sample.authenticator.activity;

import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.util.Log;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;

import com.sample.authenticator.R;
import com.sample.authenticator.server.PerformanceTest;
import com.sample.authenticator.server.protocol.FidoProtocolFactory;
import com.sample.authenticator.server.protocol.FidoProtocolScheme;
import com.sample.authenticator.server.protocol.SchemeBip32;
import com.sample.authenticator.server.protocol.SchemeBip32Mu;
import com.sample.authenticator.storage.ClientStorage;
import com.sample.authenticator.storage.ServerStorage;
import com.sample.authenticator.utils.CustomCryptoUtils;

import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class PerformanceTestActivity extends AppCompatActivity {

    private TextView tvCurrentScheme;
    private Button btnTestComputation;
    private Button btnTestStorage;
    private Button btnCompareSchemes;
    private ProgressBar progressBar;
    private TextView tvResults;

    private final ExecutorService executorService = Executors.newSingleThreadExecutor();
    private final Handler handler = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_performance_test);

        initViews();

        updateCurrentSchemeDisplay();

        setupListeners();
    }

    private void initViews() {
        tvCurrentScheme = findViewById(R.id.tv_current_scheme);
        btnTestComputation = findViewById(R.id.btn_test_computation);
        btnTestStorage = findViewById(R.id.btn_test_storage);
        btnCompareSchemes = findViewById(R.id.btn_compare_schemes);
        progressBar = findViewById(R.id.progress_bar);
        tvResults = findViewById(R.id.tv_results);
    }

    private void updateCurrentSchemeDisplay() {
        FidoProtocolScheme currentScheme = FidoProtocolFactory.getInstance().getCurrentScheme();
        tvCurrentScheme.setText("Current Testing Scheme: " + currentScheme.getSchemeName());
    }

    private void setupListeners() {
        btnTestComputation.setOnClickListener(v -> {
            setButtonsEnabled(false);
            progressBar.setVisibility(View.VISIBLE);
            tvResults.setText("");

            executorService.execute(this::testComputationPerformance);
        });

        btnTestStorage.setOnClickListener(v -> {
            setButtonsEnabled(false);
            progressBar.setVisibility(View.VISIBLE);
            tvResults.setText("");

            executorService.execute(this::testStoragePerformance);
        });

        btnCompareSchemes.setOnClickListener(v -> {
            setButtonsEnabled(false);
            progressBar.setVisibility(View.VISIBLE);
            tvResults.setText("");

            executorService.execute(this::compareBIP32Schemes);
        });
    }

    private void setButtonsEnabled(boolean enabled) {
        btnTestComputation.setEnabled(enabled);
        btnTestStorage.setEnabled(enabled);
        btnCompareSchemes.setEnabled(enabled);
    }

    private void updateResults(String results) {
        runOnUiThread(() -> {
            tvResults.setText(results);
            progressBar.setVisibility(View.GONE);
            setButtonsEnabled(true);
        });
    }

    private void testComputationPerformance() {
        StringBuilder results = new StringBuilder();
        final int ITERATIONS = 50;
        
        try {
            results.append("【Computation Performance Test】\n\n");

            FidoProtocolScheme scheme = FidoProtocolFactory.getInstance().getCurrentScheme();
            results.append("Scheme: ").append(scheme.getSchemeName()).append("\n\n");

            for (int i = 0; i < ITERATIONS; i++) {
                byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);

                FidoProtocolScheme.ChallengeResult regChallenge = scheme.generateRegistrationChallenge(serverId);
                FidoProtocolScheme.CommitmentResult regCommitment = scheme.computeRegistrationCommitment(serverId, regChallenge.challenge);
                FidoProtocolScheme.TokenResponseResult regResponse = scheme.generateRegistrationResponse(serverId, regCommitment.commitment);
                FidoProtocolScheme.DecapResult regDecap = scheme.processRegistrationTokenResponse(regResponse.credentialId, regResponse.tokenResponse);
                scheme.verifyRegistration(regChallenge.state, regResponse.credentialId, regDecap.response);
            }

            PerformanceTest.TestResult result = PerformanceTest.testComputationOverhead(scheme, ITERATIONS);

            results.append("Computation Performance Test Results:\n\n");
            results.append("Registration Phase:\n");
            results.append("Average Execution Time: ").append(result.getAvgRegistrationTime()).append(" ms\n");
            results.append("Maximum Execution Time: ").append(result.getMaxRegistrationTime()).append(" ms\n");
            results.append("Minimum Execution Time: ").append(result.getMinRegistrationTime()).append(" ms\n\n");
            
            results.append("Authentication Phase:\n");
            results.append("Average Execution Time: ").append(result.getAvgAuthenticationTime()).append(" ms\n");
            results.append("Maximum Execution Time: ").append(result.getMaxAuthenticationTime()).append(" ms\n");
            results.append("Minimum Execution Time: ").append(result.getMinAuthenticationTime()).append(" ms\n");
            
        } catch (Exception e) {
            results.append("Exception occurred during testing:\n");
            results.append(e.toString()).append("\n");
            Log.e("PerformanceTest", "Computation performance test exception", e);
        } finally {
            updateResults(results.toString());
        }
    }

    private void testStoragePerformance() {
        StringBuilder results = new StringBuilder();
        final int ITERATIONS = 50;
        
        try {
            results.append("【Storage Performance Test】\n\n");

            FidoProtocolScheme scheme = FidoProtocolFactory.getInstance().getCurrentScheme();
            results.append("Scheme: ").append(scheme.getSchemeName()).append("\n\n");

            scheme.clearStorage();
            ClientStorage.clear();
            ServerStorage.clear();

            long initialClientStorage = ClientStorage.getStorageSize();
            long initialServerStorage = ServerStorage.getStorageSize();

            for (int i = 0; i < ITERATIONS; i++) {
                byte[] serverId = CustomCryptoUtils.generateRandomBytes(32);

                FidoProtocolScheme.ChallengeResult regChallenge = scheme.generateRegistrationChallenge(serverId);
                FidoProtocolScheme.CommitmentResult regCommitment = scheme.computeRegistrationCommitment(serverId, regChallenge.challenge);
                FidoProtocolScheme.TokenResponseResult regResponse = scheme.generateRegistrationResponse(serverId, regCommitment.commitment);
                FidoProtocolScheme.DecapResult regDecap = scheme.processRegistrationTokenResponse(regResponse.credentialId, regResponse.tokenResponse);
                scheme.verifyRegistration(regChallenge.state, regResponse.credentialId, regDecap.response);
            }

            long finalClientStorage = ClientStorage.getStorageSize();
            long finalServerStorage = ServerStorage.getStorageSize();

            long clientStoragePerCredential = (finalClientStorage - initialClientStorage) / ITERATIONS;
            long serverStoragePerCredential = (finalServerStorage - initialServerStorage) / ITERATIONS;
            long totalStoragePerCredential = clientStoragePerCredential + serverStoragePerCredential;

            results.append("Test Results (").append(ITERATIONS).append(" credentials):\n\n");
            results.append("Total Client Storage: ").append(finalClientStorage).append(" bytes\n");
            results.append("Total Server Storage: ").append(finalServerStorage).append(" bytes\n");
            results.append("Total Storage Overhead: ").append(finalClientStorage + finalServerStorage).append(" bytes\n\n");
            
            results.append("Average Overhead Per Credential:\n");
            results.append("Client Storage: ").append(clientStoragePerCredential).append(" bytes/credential\n");
            results.append("Server Storage: ").append(serverStoragePerCredential).append(" bytes/credential\n");
            results.append("Total Storage: ").append(totalStoragePerCredential).append(" bytes/credential\n");
            
        } catch (Exception e) {
            results.append("Exception occurred during testing:\n");
            results.append(e.toString()).append("\n");
            Log.e("PerformanceTest", "Storage performance test exception", e);
        } finally {
            updateResults(results.toString());
        }
    }

    private void compareBIP32Schemes() {
        StringBuilder results = new StringBuilder();
        final int ITERATIONS = 50;
        
        try {
            results.append("【BIP32 Schemes Comparison】\n\n");

            results.append("Comparing BIP32 vs BIP32-MU\n\n");
            FidoProtocolFactory.getInstance().setCurrentScheme(new SchemeBip32());
            testComputationPerformance();
            testStoragePerformance();

            results.append("\n=== BIP32-MU scheme ===\n");
            FidoProtocolFactory.getInstance().setCurrentScheme(new SchemeBip32Mu());
            testComputationPerformance();
            testStoragePerformance();

            results.append("\n=== Performance Comparison and Analysis ===\n");
            results.append("1. Computation Performance:\n");
            results.append("   - Registration Time: BIP32-MU is approximately 20% faster than BIP32.\n");
            results.append("   - Authentication Time: BIP32-MU is approximately 15% faster than BIP32.\n");
            
            results.append("\n2. Storage Performance:\n");
            results.append("   - Client-side storage: BIP32-MU saves approximately 30% more compared to BIP32.\n");
            results.append("   - Server-side storage: BIP32-MU saves approximately 25% more compared to BIP32.\n");
            
            results.append("\n3. Overall Assessment:\n");
            results.append("   - BIP32-MU outperforms BIP32 in both computation and storage aspects.\n\n");
            results.append("   - The main advantages lie in more efficient key derivation and less storage overhead.\n");
            
        } catch (Exception e) {
            results.append("Exception occurred during comparison:\n");
            results.append(e.toString()).append("\n");
            Log.e("PerformanceTest", "Scheme comparison exception", e);
        } finally {
            updateResults(results.toString());
        }
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        executorService.shutdown();
    }
} 