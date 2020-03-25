package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.ConventionalCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class Client {
    private String serverAddress;
    private int port;

    private Socket socket;

    private Certificate serverCertificate;
    private Certificate clientCertificate;

    private SecretKey secretKey;

    public Client(String serverAddress, int port) {
        this.serverAddress = serverAddress;
        this.port = port;
    }

    public void load(String certificateFileName, String privateKeyFileName) throws Exception {
        clientCertificate = Certificate.read(certificateFileName, privateKeyFileName);
    }

    public void handshake() throws Exception {
        socket = new Socket(serverAddress, port);

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] randomNumberClient = generateRandomNumber(4);
        dataOutputStream.write(randomNumberClient);
        Log.d("RNc->", randomNumberClient);

        byte[] randomNumberServer = new byte[4];
        dataInputStream.read(randomNumberServer);
        Log.d("<-RNs", randomNumberServer);

        dataOutputStream.writeInt(clientCertificate.getEncoded().length);
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("CERTc->", clientCertificate.getEncoded());

        byte[] certificateBytes = new byte[184];
        dataInputStream.read(certificateBytes);
        Log.d("<-CERTs", certificateBytes);
        serverCertificate = new Certificate(certificateBytes);

        byte[] cipherText = new byte[93];
        dataInputStream.read(cipherText);
        Log.d("<-E(PMS)", cipherText);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, clientCertificate.getPrivateKey());
        byte[] preMasterSecret = cipher.doFinal(cipherText);

        byte[] salt = new byte[randomNumberClient.length + randomNumberServer.length];
        System.arraycopy(randomNumberClient, 0, salt, 0, randomNumberClient.length);
        System.arraycopy(randomNumberServer, 0, salt, randomNumberClient.length, randomNumberServer.length);

        Log.d("SALT", salt);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), salt, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Log.d("KEY", secretKey.getEncoded());

        dataInputStream.close();
        dataOutputStream.close();
    }

    public void conventionalHandshake() throws Exception {
        socket = new Socket(serverAddress, port);

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] randomNumberClient = generateRandomNumber(4);
        dataOutputStream.write(randomNumberClient);
        Log.d("RNc->", randomNumberClient);

        byte[] randomNumberServer = new byte[4];
        dataInputStream.read(randomNumberServer);
        Log.d("<-RNs", randomNumberServer);

        X509Certificate clientCertificate = ConventionalCertificate.readCertificate("c_client.dem");
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("CERTc->", clientCertificate.getEncoded());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate serverCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-CERTs", serverCertificate.toString());

        byte[] cipherText = new byte[93];
        dataInputStream.read(cipherText);
        Log.d("<-E(PMS)", cipherText);

        PrivateKey privateKey = ConventionalCertificate.readKey("c_client.key");
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] preMasterSecret = cipher.doFinal(cipherText);

        byte[] salt = new byte[randomNumberClient.length + randomNumberServer.length];
        System.arraycopy(randomNumberClient, 0, salt, 0, randomNumberClient.length);
        System.arraycopy(randomNumberServer, 0, salt, randomNumberClient.length, randomNumberServer.length);

        Log.d("SALT", salt);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), salt, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Log.d("KEY", secretKey.getEncoded());

        dataInputStream.close();
        dataOutputStream.close();
    }

    public void close() throws Exception {
        socket.close();
    }

    public void send(byte[] message) throws Exception {
        socket = new Socket(serverAddress, port);
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] nonce = generateRandomNumber(32);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(16 * 8, nonce);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, spec);

        byte[] byteCipher = cipher.doFinal(message);

        Log.d("Message", message);
        Log.d("nonce->", nonce);
        Log.d("cipher->", byteCipher);

        dataOutputStream.write(nonce);
        dataOutputStream.write(byteCipher);
        dataOutputStream.close();
    }

    public void sendWithCert(byte[] message) throws Exception {
        socket = new Socket(serverAddress, port);
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, serverCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(message);
        dataOutputStream.write(cipherText);

        Log.d("message", message);
        Log.d("cipherText->", cipherText);
    }

    public byte[] generateRandomNumber(int numBytes) throws NoSuchAlgorithmException {
        byte[] bytes = new byte[numBytes];
        SecureRandom secureRandom = SecureRandom.getInstanceStrong();
        secureRandom.nextBytes(bytes);
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        for (String arg : args) {
            System.out.println(arg);
        }

        Client client = new Client("115.145.171.29", 80);
        client.load("client.cert", "client.key");


        byte[] bytes = client.generateRandomNumber(40);
        for (int i = 0; i < 102; i++) {
//            client.send(bytes);
//            client.handshake();
            client.conventionalHandshake();
//            client.sendWithCert("Hello, World!".getBytes());
        }
        client.close();
    }
}
