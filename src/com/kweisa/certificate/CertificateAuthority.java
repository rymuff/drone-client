package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class CertificateAuthority {
    private KeyPair keyPair;
    private final String CURVE_NAME = "secp256r1";

    public CertificateAuthority() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
        keyPair = keyPairGenerator.generateKeyPair();
    }

    public CertificateAuthority(KeyPair keyPair) {
        this.keyPair = keyPair;
    }

    public static CertificateAuthority read(String fileName) throws Exception {
        byte[] publicKeyBytes = new byte[91];
        byte[] privateKeyBytes = new byte[150];

        FileInputStream fileInputStream = new FileInputStream(fileName);
        fileInputStream.read(publicKeyBytes);
        fileInputStream.read(privateKeyBytes);
        fileInputStream.close();

        PublicKey publicKey = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(publicKeyBytes));
        PrivateKey privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));

        return new CertificateAuthority(new KeyPair(publicKey, privateKey));
    }

    public void write(String fileName) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(fileName);
        fileOutputStream.write(keyPair.getPublic().getEncoded());
        fileOutputStream.write(keyPair.getPrivate().getEncoded());
        fileOutputStream.close();
    }

    public Certificate generateEncodedCertificate(byte[] version, byte[] issuer, long notBefore, long notAfter, byte[] subject) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC", BouncyCastleProvider.PROVIDER_NAME);
        keyPairGenerator.initialize(new ECGenParameterSpec(CURVE_NAME));
        KeyPair certKeyPair = keyPairGenerator.generateKeyPair();

        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
        dataOutputStream.write(version, 0, 1);
        dataOutputStream.write(issuer, 0, 2);
        dataOutputStream.writeLong(notBefore);
        dataOutputStream.writeLong(notAfter);
        dataOutputStream.write(subject, 0, 4);
        dataOutputStream.write(certKeyPair.getPublic().getEncoded());

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(byteArrayOutputStream.toByteArray());
        dataOutputStream.write(signature.sign());

        dataOutputStream.close();
        return new Certificate(byteArrayOutputStream.toByteArray(), keyPair);
    }

    public boolean verifyCertificate(Certificate certificate) throws Exception {
        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(getPublic());
        signature.update(Arrays.copyOfRange(certificate.getEncoded(), 0, 114));
        return signature.verify(certificate.getSignature());
    }

    public PrivateKey getPrivate() {
        return keyPair.getPrivate();
    }

    public PublicKey getPublic() {
        return keyPair.getPublic();
    }

    public KeyPair getKeyPair() {
        return keyPair;
    }
}
