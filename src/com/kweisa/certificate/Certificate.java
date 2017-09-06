package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class Certificate {
    private byte[] version;
    private byte[] issuer;
    private byte[] notBefore;
    private byte[] notAfter;
    private byte[] subject;
    private byte[] publicKey;
    private byte[] signature;

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

    public static Certificate read(String fileName) throws Exception {
        FileInputStream fileInputStream = new FileInputStream(fileName);
        DataInputStream dataInputStream = new DataInputStream(fileInputStream);
        byte[] bytes = new byte[fileInputStream.available()];
        dataInputStream.readFully(bytes);
        dataInputStream.close();
        fileInputStream.close();

        return new Certificate(bytes);
    }

    public void write(String fileName) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        fileOutputStream.write(getEncoded());
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

    public boolean verify(PublicKey caPublicKey) throws Exception {
        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(caPublicKey);
        signature.update(Arrays.copyOfRange(getEncoded(), 0, 114));
        return signature.verify(getSignature());
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


    public byte[] getSignature() {
        return signature;
    }

    public PublicKey getPublicKey() throws Exception {
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKey));
    }
}
