package com.kweisa.certificate;


import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.security.auth.x500.X500Principal;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Calendar;
import java.util.GregorianCalendar;

public class ConventionalCertificate {
    public static X509Certificate generateCertificate(X500Principal subjectDN, PublicKey pubKey, PrivateKey signatureKey) throws NoSuchAlgorithmException, NoSuchProviderException, CertificateException, SignatureException, InvalidKeyException {
        X509V3CertificateGenerator certGen = new X509V3CertificateGenerator();
        certGen.setSerialNumber(BigInteger.valueOf(System.currentTimeMillis()));
        certGen.setIssuerDN(subjectDN);
        certGen.setSubjectDN(subjectDN);
        GregorianCalendar currentDate = new GregorianCalendar();
        GregorianCalendar expiredDate = new GregorianCalendar(currentDate.get(Calendar.YEAR) + 2, currentDate.get(Calendar.MONTH), currentDate.get(Calendar.DAY_OF_MONTH));
        certGen.setNotBefore(currentDate.getTime());
        certGen.setNotAfter(expiredDate.getTime());
        certGen.setPublicKey(pubKey);
        certGen.setSignatureAlgorithm("SHA512withECDSA");
        certGen.addExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));
        return certGen.generate(signatureKey, "BC");
    }

    public static PrivateKey readKey(String fileName) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        byte[] privateKeyBytes = new byte[150];
        FileInputStream fileInputStream = new FileInputStream(new File(fileName));
        fileInputStream.read(privateKeyBytes);
        fileInputStream.close();

        return KeyFactory.getInstance("ECDSA", BouncyCastleProvider.PROVIDER_NAME).generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
    }

    public static void writeKey(String fileName, byte[] encoded) throws IOException {
        FileOutputStream fileOutputStream = new FileOutputStream(new File(fileName));
        fileOutputStream.write(encoded);
        fileOutputStream.close();
    }

    public static X509Certificate readCertificate(String fileName) throws CertificateException, IOException {
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        FileInputStream fileInputStream = new FileInputStream(new File(fileName));
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        fileInputStream.close();

        return certificate;
    }

    public static void writeCertificate(String fileName, X509Certificate certificate) throws IOException, CertificateEncodingException {
        FileOutputStream fileOutputStream = new FileOutputStream(new File(fileName));
        fileOutputStream.write(certificate.getEncoded());
        fileOutputStream.close();
    }
}
