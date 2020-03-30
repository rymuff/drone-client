package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.CertificateAuthority;
import com.kweisa.certificate.ConventionalCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Client {
    private String serverAddress;
    private int port;
    private Socket socket;
    DataInputStream dataInputStream;
    DataOutputStream dataOutputStream;
    SecureRandom secureRandom;

    private Certificate serverCertificate;
    private Certificate clientCertificate;
    private CertificateAuthority certificateAuthority;

    private SecretKey secretKey;

    public Client(String serverAddress, int port) throws NoSuchAlgorithmException {
        this.serverAddress = serverAddress;
        this.port = port;
        secureRandom = SecureRandom.getInstanceStrong();
    }

    public void load(String certificateFileName, String privateKeyFileName, String caKeyFileName) throws Exception {
        clientCertificate = Certificate.read(certificateFileName, privateKeyFileName);
        certificateAuthority = CertificateAuthority.read(caKeyFileName);
    }

    public void connect() throws IOException {
        socket = new Socket(serverAddress, port);
        dataInputStream = new DataInputStream(socket.getInputStream());
        dataOutputStream = new DataOutputStream(socket.getOutputStream());
    }

    public void close() throws Exception {
        dataInputStream.close();
        dataOutputStream.close();

        socket.close();
    }

    public void write(byte[] message) throws IOException {
        dataOutputStream.writeShort(message.length);
        dataOutputStream.write(message);

        Log.write(message);
    }

    public byte[] read() throws IOException {
        short size = dataInputStream.readShort();
        byte[] message = new byte[size];
        dataInputStream.read(message);
        Log.read(message);
        return message;
    }


    public void handshake() throws Exception {
        // 1a
        byte[] nonceClient = new byte[4];
        secureRandom.nextBytes(nonceClient);
        Log.d("Nc", nonceClient);

        // 1b
        write(clientCertificate.getSubject());
        write(nonceClient);
        write(clientCertificate.getEncoded());

        // 2b
        byte[] nonce = read();
        byte[] signatureNonce = read();
        byte[] serverCertificateBytes = read();

        // 3
        serverCertificate = new Certificate(serverCertificateBytes);
        boolean validity = certificateAuthority.verifyCertificate(serverCertificate);
        Log.d("CERTs", validity);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(serverCertificate.getPublicKey());
        signature.update(nonce);
        validity = signature.verify(signatureNonce);
        Log.d("SIG(Nd, Ngs)", validity);

        // 4b
        byte[] cipherText = read();
        byte[] signaturePms = read();

        // 5
        signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(serverCertificate.getPublicKey());
        signature.update(cipherText);
        validity = signature.verify(signaturePms);
        Log.d("SIG(E(PMS))", validity);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, clientCertificate.getPrivateKey());
        byte[] preMasterSecret = cipher.doFinal(cipherText);
        Log.d("PMS", preMasterSecret);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), nonce, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Log.d("MS", secretKey.getEncoded());
    }

    public void handshakeOld() throws Exception {
        // 1
        byte[] clientHello = new byte[1];
        secureRandom.nextBytes(clientHello);
        write(clientHello);

        // 2
        byte[] serverHello = read();

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate serverCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-", serverCertificate.getEncoded());

        // 3
        byte[] request = read();

        // 4
        X509Certificate clientCertificate = ConventionalCertificate.readCertificate("c_client.dem");
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("->", clientCertificate.getEncoded());

        // 5
        byte[] preMasterSecret = new byte[16];
        secureRandom.nextBytes(preMasterSecret);
        Log.d("PMS", preMasterSecret);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, serverCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);
        write(cipherText);
        Log.d("E(PMS)->", cipherText);

        // 6
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        byteArrayOutputStream.write(clientHello);
        byteArrayOutputStream.write(serverHello);
        byteArrayOutputStream.write(serverCertificate.getEncoded());
        byteArrayOutputStream.write(request);
        byteArrayOutputStream.write(clientCertificate.getEncoded());
        byteArrayOutputStream.write(cipherText);
        byte[] message = byteArrayOutputStream.toByteArray();

        PrivateKey privateKey = ConventionalCertificate.readKey("c_client.key");
        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(privateKey);
        signature.update(message);
        byte[] sig = signature.sign();
        write(sig);

        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), preMasterSecret, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Log.d("MS", secretKey.getEncoded());

        // 7
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, preMasterSecret);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] finishedMessage = cipher.doFinal("Finished".getBytes());
        write(finishedMessage);

        // 8
        finishedMessage = read();
    }

    public void authenticate() throws Exception {
        byte[] message = new byte[40];
        secureRandom.nextBytes(message);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hash = mac.doFinal(message);

        write(hash);
        write(message);
    }

    public void authenticateOld() throws Exception {
        byte[] message = new byte[40];
        secureRandom.nextBytes(message);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(clientCertificate.getPrivateKey());
        signature.update(message);
        byte[] sign = signature.sign();

        write(sign);
        write(message);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Client client = new Client("115.145.171.29", 80);
        client.load("client.cert", "client.key", "ca.keypair");
        client.connect();

        client.handshake();
        client.authenticate();

        client.close();
    }
}
