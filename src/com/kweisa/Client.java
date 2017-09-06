package com.kweisa;

import com.kweisa.certificate.Certificate;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;


public class Client {
    private String serverAddress;
    private int port;
    private Certificate certificate;

    public Client(String serverAddress, int port) {
        this.serverAddress = serverAddress;
        this.port = port;
    }

    public void load(String certificateFileName, String privateKeyFileName) throws Exception {
        certificate = Certificate.read(certificateFileName, privateKeyFileName);
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

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Client client = new Client("127.0.0.1", 10002);
        client.load("client.cert", "client.key");
        client.connect();
    }
}
