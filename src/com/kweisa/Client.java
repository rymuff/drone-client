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
import java.util.Arrays;

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

    public void handshake() throws Exception {
        // 1a. client hello
        dataOutputStream.writeBoolean(true);
        Log.d("Hello->", "true");

        // 1b. server hello
        boolean serverHello = dataInputStream.readBoolean();
        Log.d("<-Hello", serverHello);

        // 2a. choose nonce of drone nd
        byte[] nonceClient = new byte[4];
        secureRandom.nextBytes(nonceClient);
        Log.d("Nc", nonceClient);

        // 2b. send nd
        dataOutputStream.write(nonceClient);
        Log.d("Nc->", nonceClient);

        // 3a. choose nonce of ground station ngs
        // 3b. sign nd, ngs
        // 3c. send nd, ngs, certgs and sign(nd, ngs) 184
        byte[] nonce = new byte[8];
        byte[] serverCertificateBytes = new byte[184];
        byte[] sign = new byte[1024];
        dataInputStream.read(nonce);
        dataInputStream.read(serverCertificateBytes);
        int length = dataInputStream.read(sign);
        sign = Arrays.copyOf(sign, length);
        Log.d("<-Nc+Ns", nonce);
        Log.d("<-CERTs", serverCertificateBytes);
        Log.d("<-SIGN", sign);


        // 4. check the validity of certgs
        serverCertificate = new Certificate(serverCertificateBytes);
        boolean validity = certificateAuthority.verifyCertificate(serverCertificate);
        Log.d("CERTs", validity);

        // 4. extract gs'spublickey of pkgs from cergs, check the validity of sign(nd, ngs)
        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initVerify(serverCertificate.getPublicKey());
        signature.update(nonce);
        validity = signature.verify(sign);
        Log.d("SIGN", validity);

        // 5. send certd
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("CERTc->", clientCertificate.getEncoded());

        // 6a. check the validity of certd, extract d's publickey of pkd from certd, encrypt e(pms) with pkd
        // 6b. send e(pms)
        byte[] cipherText = new byte[1024];
        length = dataInputStream.read(cipherText);
        cipherText = Arrays.copyOf(cipherText, length);
        Log.d("<-E(PMS)", cipherText);

        // 7. decrypt e(pms)
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE, clientCertificate.getPrivateKey());
        byte[] preMasterSecret = cipher.doFinal(cipherText);
        Log.d("PMS", preMasterSecret);

        // 7. compute master secret
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), nonce, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "HmacSHA256");
        Log.d("MS", secretKey.getEncoded());
    }

    public void handshakeOld() throws Exception {
        // 1. client hello
        byte[] clientHello = new byte[1];
        secureRandom.nextBytes(clientHello);
        dataOutputStream.write(clientHello);
        Log.d("Hello->", clientHello);

        // 2a. server hello
        byte[] serverHello = new byte[1];
        dataInputStream.read(serverHello);
        Log.d("<-Hello", serverHello);

        // 2b. server hello
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate serverCertificate = (X509Certificate) certificateFactory.generateCertificate(dataInputStream);
        Log.d("<-CERTs", serverCertificate.getEncoded());

        // 3. cert request
        byte[] request = new byte[1];
        dataInputStream.read(request);
        Log.d("<-REQUEST", request);

        // 4. send certd
        X509Certificate clientCertificate = ConventionalCertificate.readCertificate("c_client.dem");
        dataOutputStream.write(clientCertificate.getEncoded());
        Log.d("CERTc->", clientCertificate.getEncoded());

        // 5. KEY INFO
        byte[] preMasterSecret = new byte[16];
        secureRandom.nextBytes(preMasterSecret);
        Log.d("PMS", preMasterSecret);

        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, serverCertificate.getPublicKey());
        byte[] cipherText = cipher.doFinal(preMasterSecret);
        dataOutputStream.write(cipherText);
        Log.d("E(PMS)->", cipherText);

        // 6. certificate verify
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
        dataOutputStream.writeInt(sig.length);
        dataOutputStream.write(sig);
        Log.d("sig->", sig);

        // -. calculate symmetric key
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBKDF2withHmacSHA256");
        secretKey = secretKeyFactory.generateSecret(new PBEKeySpec(new String(preMasterSecret).toCharArray(), preMasterSecret, 10000, 256));
        secretKey = new SecretKeySpec(secretKey.getEncoded(), "AES");
        Log.d("MS", secretKey.getEncoded());

        // 7. finishedMessage
        cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(16 * 8, preMasterSecret);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, gcmParameterSpec);
        byte[] finishedMessage = cipher.doFinal("Finished".getBytes());
        dataOutputStream.write(finishedMessage);
        Log.d("finishedMessage->", finishedMessage);

        // 8. finishedMessage
        finishedMessage = new byte[1024];
        int length = dataInputStream.read(finishedMessage);
        finishedMessage = Arrays.copyOf(finishedMessage, length);
        Log.d("<-finishedMessage", finishedMessage);
    }

    public void authenticate() throws Exception {
        byte[] message = new byte[40];
        secureRandom.nextBytes(message);

        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(secretKey);
        byte[] hash = mac.doFinal(message);

        dataOutputStream.write(message);
        dataOutputStream.write(hash);
        Log.d("message->", message);
        Log.d("hash->", hash);

        dataInputStream.read(message);
        dataInputStream.read(hash);
        Log.d("<-message", message);
        Log.d("<-hash", hash);

        byte[] bytes = mac.doFinal(message);
        Log.d("Verified", Arrays.equals(hash, bytes));
    }

    public void authenticateOld() throws Exception {
        byte[] message = new byte[40];
        secureRandom.nextBytes(message);

        Signature signature = Signature.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME);
        signature.initSign(clientCertificate.getPrivateKey());
        signature.update(message);
        byte[] sign = signature.sign();

        dataOutputStream.write(message);
        dataOutputStream.write(sign);
        Log.d("message->", message);
        Log.d("sign->", sign);

        sign = new byte[128];
        dataInputStream.read(message);
        int length = dataInputStream.read(sign);
        sign = Arrays.copyOf(sign, length);
        Log.d("<-message", message);
        Log.d("<-sign", sign);

        signature.initVerify(serverCertificate.getPublicKey());
        signature.update(message);
        boolean validity = signature.verify(sign);
        Log.d("SIGN", validity);
    }

    public static void main(String[] args) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        Client client = new Client("115.145.171.29", 80);
        client.load("client.cert", "client.key", "ca.keypair");
        client.connect();

//        client.handshake();
//        client.handshakeOld();
//            client.authenticate();
//        client.authenticateOld();

        for (int i = 0; i < 200; i++) {
//            client.handshake();
            client.handshakeOld();
//            client.authenticate();
//            client.authenticateOld();
        }

        client.close();
    }
}
