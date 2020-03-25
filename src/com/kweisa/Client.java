package com.kweisa;

import com.kweisa.certificate.Certificate;
import com.kweisa.certificate.ConventionalCertificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;


public class Client {
    private String serverAddress;
    private int port;

    private Socket socket;

    private Certificate certificate;

    private SecretKey secretKey;

    public Client(String serverAddress, int port) {
        this.serverAddress = serverAddress;
        this.port = port;
    }

    public void load(String certificateFileName, String privateKeyFileName) throws Exception {
        certificate = Certificate.read(certificateFileName, privateKeyFileName);
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

        dataOutputStream.writeInt(certificate.getEncoded().length);
        dataOutputStream.write(certificate.getEncoded());
        Log.d("CERTc->", certificate.getEncoded());

        byte[] certificateBytes = new byte[184];
        dataInputStream.read(certificateBytes);
        Log.d("<-CERTs", certificateBytes);
        Certificate serverCertificate = new Certificate(certificateBytes);

        byte[] preMasterSecret = generateRandomNumber(8);
        Log.d("PMS->", preMasterSecret);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, serverCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);
        dataOutputStream.write(cipherText);

        Log.d("PMS->", cipherText);
        Log.d("PMS->", "" + cipherText.length);

        byte[] salt = new byte[randomNumberClient.length + randomNumberServer.length];
        System.arraycopy(randomNumberClient, 0, salt, 0, randomNumberClient.length);
        System.arraycopy(randomNumberServer, 0, salt, randomNumberClient.length, randomNumberServer.length);

        Log.d("SALT", salt);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), salt, 1024, 128));
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

        X509Certificate clientCertificate = ConventionalCertificate.readCertificate("covclient.dem");
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("CERTc->", clientCertificate.getEncoded());

        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate serverCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-CERTs", serverCertificate.toString());

        byte[] preMasterSecret = generateRandomNumber(8);
        Log.d("PMS", preMasterSecret);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, serverCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);
        dataOutputStream.write(cipherText);

        Log.d("PMS->", cipherText);

        byte[] salt = new byte[randomNumberClient.length + randomNumberServer.length];
        System.arraycopy(randomNumberClient, 0, salt, 0, randomNumberClient.length);
        System.arraycopy(randomNumberServer, 0, salt, randomNumberClient.length, randomNumberServer.length);

        Log.d("SALT", salt);
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA1");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), salt, 1024, 128));
        Log.d("KEY", secretKey.getEncoded());

        dataInputStream.close();
        dataOutputStream.close();
    }


    public void close() throws Exception {
        socket.close();
    }

    public void send(byte[] message) throws Exception {
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());
        Mac mac = Mac.getInstance("HmacMD5");
        mac.init(secretKey);
        byte[] hmac = mac.doFinal(message);

        Log.d("HAMC", hmac);
        Log.d("Message", message);

        dataOutputStream.write(hmac);
        dataOutputStream.write(message);
        dataOutputStream.close();
    }

    public byte[] generateRandomNumber(int numBytes) {
        byte[] bytes = new byte[numBytes];
        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.setSeed(secureRandom.generateSeed(numBytes));
            secureRandom.nextBytes(bytes);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return bytes;
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        for (String arg : args) {
            System.out.println(arg);
        }

        Client client = new Client("115.145.171.29", 7749);
        client.load("client.cert", "client.key");

        for (int i = 0; i < 100; i++) {
            client.conventionalHandshake();
//            client.handshake();
        }
        client.close();
    }
}
