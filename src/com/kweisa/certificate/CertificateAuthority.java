package com.kweisa.certificate;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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

    public static CertificateAuthority read(String fileName) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
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

    public byte[] generateEncodedCertificate(byte[] version, byte[] issuer, long notBefore, long notAfter, byte[] subject, KeyPair certKeyPair) throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        DataOutputStream dataOutputStream = new DataOutputStream(byteArrayOutputStream);
        dataOutputStream.write(version);
        dataOutputStream.write(issuer);
        dataOutputStream.writeLong(notBefore);
        dataOutputStream.writeLong(notAfter);
        dataOutputStream.write(subject);
        dataOutputStream.write(certKeyPair.getPublic().getEncoded());

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(keyPair.getPrivate());
        signature.update(byteArrayOutputStream.toByteArray());
        dataOutputStream.write(signature.sign());

        dataOutputStream.close();
        return byteArrayOutputStream.toByteArray();
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
