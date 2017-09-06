package com.kweisa;


import org.bouncycastle.util.encoders.Hex;

public class Log {
    public static void d(String tag, String message) {
        System.out.println(tag + ": " + message);
    }

    public static void d(String tag, byte[] message) {
        System.out.println(tag + ": " + Hex.toHexString(message));
    }
}
