package com.sample.authenticator.server;

import android.content.Context;
import android.content.SharedPreferences;


public class FidoServerFactory {
    

    public static final int SERVER_TYPE_SIMULATOR = 0;
    public static final int SERVER_TYPE_PC = 1;
    

    private static int serverType = SERVER_TYPE_SIMULATOR;
    

    private static String pcServerAddress = "http://localhost:8080";
    

    private static final String PREF_NAME = "fido_server_settings";
    private static final String KEY_SERVER_TYPE = "server_type";
    private static final String KEY_PC_SERVER_ADDRESS = "pc_server_address";
    
    private FidoServerFactory() {

    }
    

    public static void init(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        serverType = prefs.getInt(KEY_SERVER_TYPE, SERVER_TYPE_SIMULATOR);
        pcServerAddress = prefs.getString(KEY_PC_SERVER_ADDRESS, pcServerAddress);
    }
    

    public static void saveSettings(Context context) {
        SharedPreferences prefs = context.getSharedPreferences(PREF_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor editor = prefs.edit();
        editor.putInt(KEY_SERVER_TYPE, serverType);
        editor.putString(KEY_PC_SERVER_ADDRESS, pcServerAddress);
        editor.apply();
    }
    

    public static IFidoServer createServer() {
        switch (serverType) {
            case SERVER_TYPE_PC:
                return new PcFidoServer(pcServerAddress);
            case SERVER_TYPE_SIMULATOR:
            default:
                return new FidoServerSimulator();
        }
    }
    

    public static int getServerType() {
        return serverType;
    }
    

    public static void setServerType(int type) {
        if (type != SERVER_TYPE_SIMULATOR && type != SERVER_TYPE_PC) {
            throw new IllegalArgumentException("Invalid server type");
        }
        serverType = type;
    }
    

    public static String getPcServerAddress() {
        return pcServerAddress;
    }
    

    public static void setPcServerAddress(String address) {
        pcServerAddress = address;
    }
} 