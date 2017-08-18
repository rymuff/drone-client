package com.kweisa;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;



public class Client {
    private String serverAddress;
    private int port;

    public Client(String serverAddress, int port) {
        this.serverAddress = serverAddress;
        this.port = port;
    }

    public void connect() throws IOException, NoSuchAlgorithmException {
        Socket socket = new Socket(serverAddress,port);

        DataInputStream dataInputStream = new DataInputStream(socket.getInputStream());
        DataOutputStream dataOutputStream = new DataOutputStream(socket.getOutputStream());

        byte[] randomNumberClient = generateRandomNumber(4);
        dataOutputStream.write(randomNumberClient);
        Log.d("RNc->", randomNumberClient);

        byte[] randomNumberServer = new byte[4];
        dataInputStream.read(randomNumberServer);
        Log.d("<-RNs", randomNumberServer);


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
        for(byte b: a)
            sb.append(String.format("%02x", b));
        return sb.toString();
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        Client client = new Client("127.0.0.1", 10002);
        client.connect();
    }
}
