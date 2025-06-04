package com.sample.authenticator.server.protocol;

import java.util.ArrayList;
import java.util.List;

public class FidoProtocolFactory {

    private static FidoProtocolFactory instance;

    private final List<FidoProtocolScheme> schemes = new ArrayList<>();

    private int currentSchemeIndex = 0;

    private FidoProtocolFactory() {
        schemes.add(new SchemeBip32());
        schemes.add(new SchemeBip32Mu());
        schemes.add(new SchemeBip32Su());
        schemes.add(new SchemeBip32MuPlus());
        schemes.add(new SchemeBip32SuPlus());
        schemes.add(new SchemeBip32Plus());
    }
    

    public static synchronized FidoProtocolFactory getInstance() {
        if (instance == null) {
            instance = new FidoProtocolFactory();
        }
        return instance;
    }
    

    public FidoProtocolScheme getCurrentScheme() {
        return schemes.get(currentSchemeIndex);
    }
    

    public List<FidoProtocolScheme> getSchemes() {
        return schemes;
    }

    public FidoProtocolScheme getScheme(int index) {
        if (index < 0 || index >= schemes.size()) {
            throw new IllegalArgumentException("Protocol scheme index out of range");
        }
        return schemes.get(index);
    }
    

    public void setCurrentScheme(int index) {
        if (index < 0 || index >= schemes.size()) {
            throw new IllegalArgumentException("Protocol scheme index out of range");
        }
        this.currentSchemeIndex = index;
    }
    

    public void setCurrentScheme(FidoProtocolScheme scheme) {
        int index = schemes.indexOf(scheme);
        if (index >= 0) {
            this.currentSchemeIndex = index;
        } else {
            schemes.add(scheme);
            this.currentSchemeIndex = schemes.size() - 1;
        }
    }
    

    public int getSchemeCount() {
        return schemes.size();
    }
    

    public String[] getSchemeNames() {
        String[] names = new String[schemes.size()];
        for (int i = 0; i < schemes.size(); i++) {
            names[i] = schemes.get(i).getSchemeName();
        }
        return names;
    }
    

    public void clearAllStorage() {
        for (FidoProtocolScheme scheme : schemes) {
            scheme.clearStorage();
        }
    }
} 