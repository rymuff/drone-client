package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Certificate {
    private byte[] version;
    private byte[] issuer;
    private byte[] notBefore;
    private byte[] notAfter;
    private byte[] subject;
    private byte[] publicKey;
    private byte[] signature;
    private KeyPair keyPair;

    public Certificate(byte[] bytes) {
        version = new byte[1];
        issuer = new byte[2];
        notBefore = new byte[8];
        notAfter = new byte[8];
        subject = new byte[4];
        publicKey = new byte[91];
        signature = new byte[bytes.length - 1 - 2 - 8 - 8 - 4 - 91];

        putBytes(bytes);
    }

    public Certificate(byte[] bytes, KeyPair keyPair) {
        version = new byte[1];
        issuer = new byte[2];
        notBefore = new byte[8];
        notAfter = new byte[8];
        subject = new byte[4];
        publicKey = new byte[91];
        signature = new byte[bytes.length - 1 - 2 - 8 - 8 - 4 - 91];

        this.keyPair = keyPair;

        putBytes(bytes);
    }

    public Certificate(byte[] certificateBytes, byte[] privateKeyBytes) throws Exception {
        version = new byte[1];
        issuer = new byte[2];
        notBefore = new byte[8];
        notAfter = new byte[8];
        subject = new byte[4];
        publicKey = new byte[91];
        signature = new byte[certificateBytes.length - 1 - 2 - 8 - 8 - 4 - 91];

        putBytes(certificateBytes);

        PublicKey publicKey = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(this.publicKey));
        PrivateKey privateKey = KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        this.keyPair = new KeyPair(publicKey, privateKey);
    }

    public static Certificate read(String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);
        byte[] bytes = new byte[fileInputStream.available()];
        dataInputStream.readFully(bytes);
        dataInputStream.close();
        fileInputStream.close();

        return new Certificate(bytes);
    }

    public static Certificate read(String certificateFileName, String privateKeyFileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(certificateFileName);
        byte[] certificateBytes = new byte[fileInputStream.available()];
        fileInputStream.read(certificateBytes);
        fileInputStream.close();

        fileInputStream = new FileInputStream(privateKeyFileName);
        byte[] privateKeyBytes = new byte[fileInputStream.available()];
        fileInputStream.read(privateKeyBytes);
        fileInputStream.close();

        return new Certificate(certificateBytes, privateKeyBytes);
    }

    public void write(String fileName) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        fileOutputStream.write(getEncoded());
        fileOutputStream.close();
    }

    public void write(String certificateFileName, String privateKeyFileName) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(certificateFileName);
        fileOutputStream.write(getEncoded());
        fileOutputStream.close();

        fileOutputStream = new FileOutputStream(privateKeyFileName);
        fileOutputStream.write(keyPair.getPrivate().getEncoded());
        fileOutputStream.close();
    }

    private void putBytes(byte[] bytes) {
        ByteBuffer byteBuffer = ByteBuffer.wrap(bytes);
        byteBuffer.get(version);
        byteBuffer.get(issuer);
        byteBuffer.get(notBefore);
        byteBuffer.get(notAfter);
        byteBuffer.get(subject);
        byteBuffer.get(publicKey);
        byteBuffer.get(signature);
    }

    public byte[] getEncoded() throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
        dataOutputStream.write(version);
        dataOutputStream.write(issuer);
        dataOutputStream.write(notBefore);
        dataOutputStream.write(notAfter);
        dataOutputStream.write(subject);
        dataOutputStream.write(publicKey);
        dataOutputStream.write(signature);
        dataOutputStream.close();

        return byteArrayOutputStream.toByteArray();
    }

    public byte[] getVersion() {
        return version;
    }

    public byte[] getIssuer() {
        return issuer;
    }

    public long getNotBefore() {
        return ByteBuffer.wrap(notBefore).getLong();
    }

    public long getNotAfter() {
        return ByteBuffer.wrap(notAfter).getLong();
    }

    public byte[] getSubject() {
        return subject;
    }

    public PublicKey getPublicKey() throws Exception {
        return KeyFactory.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME).generatePublic(new X509EncodedKeySpec(publicKey));
    }

    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    public byte[] getSignature() {
        return signature;
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
