package com.kweisa;

import com.kweisa.certificate.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;


public class Client {
    private String serverAddress;
    private int port;
    private Certificate certificate;
    private PrivateKey privateKey;

    public Client(String serverAddress, int port) {
        this.serverAddress = serverAddress;
        this.port = port;

    }

    public void load(String certificateFileName, String privateKeyFileName) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        certificate = Certificate.read(certificateFileName);

        FileInputStream fileInputStream = new FileInputStream(privateKeyFileName);
        byte[] bytes = new byte[fileInputStream.available()];
        fileInputStream.read(bytes);
        fileInputStream.close();

        privateKey = KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(bytes));
    }

    public void connect() throws IOException, NoSuchAlgorithmException {
        Socket socket = new Socket(serverAddress, port);

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] randomNumberClient = generateRandomNumber(4);
        dataOutputStream.write(randomNumberClient);
        Log.d("RNc->", randomNumberClient);

        byte[] randomNumberServer = new byte[4];
        dataInputStream.read(randomNumberServer);
        Log.d("<-RNs", randomNumberServer);

        dataOutputStream.write(certificate.getEncoded());
        Log.d("CERTc->", certificate.getEncoded());

        dataInputStream.close();
        dataOutputStream.close();
        socket.close();
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

    public static String byteArrayToHex(byte[] a) {
        StringBuilder sb = new StringBuilder(a.length * 2);
        for (byte b : a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws Exception {
        Client client = new Client("127.0.0.1", 10002);
        client.load("client.cert", "client.key");
        client.connect();
    }
}
