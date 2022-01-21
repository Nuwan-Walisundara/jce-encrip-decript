package com.example.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Genarate public & private key . reffer https://blog.jonm.dev/posts/rsa-public-key-cryptography-in-java/
 * Hello world!
 *
 */
public class App {
    public static void main(String[] args) {

        try {

            File publicKeyFile = new File("/Users/nuwanwalisundara/poc/security/public_key.der");
            byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

            KeyFactory keyFactory = KeyFactory.getInstance("RSA");

            File privateKeyFile = new File("/Users/nuwanwalisundara/poc/security/private_key.der");
            byte[] privateKeyBytes = Files.readAllBytes(privateKeyFile.toPath());
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

            PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
            Cipher encryptCipher = Cipher.getInstance("RSA");
            encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);

            String secretMessage = "Baeldung secret message";

            byte[] secretMessageBytes = secretMessage.getBytes(StandardCharsets.UTF_8);
            byte[] encryptedMessageBytes = encryptCipher.doFinal(secretMessageBytes);

            String encriptedStr = new String(encryptedMessageBytes);
            System.out.println("This is the encripted message"+ encriptedStr);
            Cipher decryptCipher = Cipher.getInstance("RSA");
            decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);

            byte[] decryptedMessageBytes = decryptCipher.doFinal(encryptedMessageBytes);
            String decryptedMessage = new String(decryptedMessageBytes, StandardCharsets.UTF_8);

            System.out.println("This is the decrepted message"+ decryptedMessage);

        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }

    }
}
