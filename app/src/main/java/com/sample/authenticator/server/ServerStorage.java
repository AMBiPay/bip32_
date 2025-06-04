package com.sample.authenticator.server;

import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;


public class ServerStorage {
    // Store the mapping from cid to server registration context, i.e., rcs[cid] = (pk, rsA)
    private static final Map<String, ServerContext> rcsMap = new HashMap<>();
    

    public static class ServerContext {
        private final PublicKey pk;
        private final byte[] extraData;
        
        public ServerContext(PublicKey pk, byte[] extraData) {
            this.pk = pk;
            this.extraData = extraData;
        }
        
        public PublicKey getPublicKey() {
            return pk;
        }
        
        public byte[] getExtraData() {
            return extraData;
        }
    }
    

    public static void saveRcs(byte[] cid, PublicKey pk, byte[] extraData) {
        String cidKey = ByteUtils.byte2base64(cid);
        ServerContext context = new ServerContext(pk, extraData);
        rcsMap.put(cidKey, context);
    }
    

    public static ServerContext getRcs(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        return rcsMap.get(cidKey);
    }
    

    public static void updateRcs(byte[] cid, PublicKey pk, byte[] extraData) {
        saveRcs(cid, pk, extraData);
    }
    

    public static void removeRcs(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        rcsMap.remove(cidKey);
    }
    

    public static boolean hasCid(byte[] cid) {
        String cidKey = ByteUtils.byte2base64(cid);
        return rcsMap.containsKey(cidKey);
    }
    

    public static void clear() {
        rcsMap.clear();
    }
    

    public static long getStorageSize() {
        long size = 0;
        for (Map.Entry<String, ServerContext> entry : rcsMap.entrySet()) {

            size += entry.getKey().length() * 2;
            

            ServerContext context = entry.getValue();
            if (context != null) {

                size += 256;
                

                if (context.getExtraData() != null) {
                    size += context.getExtraData().length;
                }
            }
        }
        return size;
    }
} 