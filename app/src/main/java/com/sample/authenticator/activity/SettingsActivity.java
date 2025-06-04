package com.sample.authenticator.activity;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.Toast;

import androidx.appcompat.app.AppCompatActivity;

import com.sample.authenticator.R;
import com.sample.authenticator.server.FidoServerFactory;

public class SettingsActivity extends AppCompatActivity {

    private RadioGroup rgServerType;
    private RadioButton rbSimulator;
    private RadioButton rbPcServer;
    private EditText etPcServerAddress;
    private Button btnSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        initViews();

        loadCurrentSettings();

        setupListeners();
    }

    private void initViews() {
        rgServerType = findViewById(R.id.rg_server_type);
        rbSimulator = findViewById(R.id.rb_simulator);
        rbPcServer = findViewById(R.id.rb_pc_server);
        etPcServerAddress = findViewById(R.id.et_pc_server_address);
        btnSave = findViewById(R.id.btn_save);
    }

    private void loadCurrentSettings() {
        FidoServerFactory.init(this);

        int serverType = FidoServerFactory.getServerType();

        if (serverType == FidoServerFactory.SERVER_TYPE_SIMULATOR) {
            rbSimulator.setChecked(true);
            etPcServerAddress.setEnabled(false);
        } else {
            rbPcServer.setChecked(true);
            etPcServerAddress.setEnabled(true);
        }

        etPcServerAddress.setText(FidoServerFactory.getPcServerAddress());
    }

    private void setupListeners() {
        rgServerType.setOnCheckedChangeListener((group, checkedId) -> {
            if (checkedId == R.id.rb_simulator) {
                etPcServerAddress.setEnabled(false);
            } else {
                etPcServerAddress.setEnabled(true);
            }
        });

        btnSave.setOnClickListener(v -> saveSettings());
    }

    private void saveSettings() {
        int serverType = rbSimulator.isChecked() ? 
                FidoServerFactory.SERVER_TYPE_SIMULATOR : 
                FidoServerFactory.SERVER_TYPE_PC;

        String pcServerAddress = etPcServerAddress.getText().toString().trim();

        if (serverType == FidoServerFactory.SERVER_TYPE_PC && pcServerAddress.isEmpty()) {
            Toast.makeText(this, "Please enter the address of the PC server", Toast.LENGTH_SHORT).show();
            return;
        }

        FidoServerFactory.setServerType(serverType);
        FidoServerFactory.setPcServerAddress(pcServerAddress);
        FidoServerFactory.saveSettings();
        
        Toast.makeText(this, "The settings have been saved", Toast.LENGTH_SHORT).show();
        finish();
    }
} 