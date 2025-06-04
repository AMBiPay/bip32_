package com.sample.authenticator.server;

import java.util.HashMap;
import java.util.Map;

public class ClientStorage {
    private static final Map<String, byte[]> pcsMap = new HashMap<>();
    

    public static void saveCredentialData(byte[] cid, byte[] data) {
        String cidKey = ByteUtils.byte2base64(cid);
        pcsMap.put(cidKey, data);
    }

    public static byte[] getCredentialData(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        return pcsMap.get(cidKey);
    }
    

    public static void updateCredentialData(byte[] cid, byte[] newData) {
        saveCredentialData(cid, newData);
    }

    public static void removeCredentialData(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        pcsMap.remove(cidKey);
    }
    

    public static boolean hasCredentialId(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        return pcsMap.containsKey(cidKey);
    }

    public static void clear() {
        pcsMap.clear();
    }
    

    public static long getStorageSize() {
        long size = 0;
        for (Map.Entry<String, byte[]> entry : pcsMap.entrySet()) {

            size += entry.getKey().length() * 2;
            if (entry.getValue() != null) {
                size += entry.getValue().length;
            }
        }
        return size;
    }
} 