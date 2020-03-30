package com.kweisa;


import org.bouncycastle.util.encoders.Hex;

public class Log {
    public static void d(String tag, String message) {
        System.out.println(tag + ": " + message);
    }

    public static void d(String tag, byte[] message) {
        System.out.println(tag + " [" + message.length + "] " + ": " + Hex.toHexString(message));
    }

    public static void write(byte[] message) {
        d("->", message);
    }

    public static void read(byte[] message) {
        d("<-", message);
    }

    public static void d(String tag, boolean message) {
        System.out.println(tag + ": " + message);
    }
}
