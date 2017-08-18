package com.kweisa;


public class Log {
    public static void d(String tag, String message) {
        System.out.println(tag + ": " + message);
    }

    public static void d(String tag, byte[] message) {
        System.out.println(tag + ": " + byteArrayToHex(message));
    }

    private static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }
}
