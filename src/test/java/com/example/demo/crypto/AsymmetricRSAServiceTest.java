package com.example.demo.crypto;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Assertions;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class AsymmetricRSAServiceTest {

    @Test
    public void testRSA() throws Exception {
        AsymmetricRSAService asymmetricRSAService = new AsymmetricRSAService();
        String plainText = "Hello World!";
        KeyPair keyPair = asymmetricRSAService.getRSAKeys();

        PrivateKey privateKey = keyPair.getPrivate();
        PublicKey publicKey = keyPair.getPublic();

        byte[] encryptedText = asymmetricRSAService.encryptMessage(plainText, privateKey);
        System.out.println("Encrypted:" + getEncodedString(encryptedText));

        byte[] decryptedText = asymmetricRSAService.decryptMessage(encryptedText, publicKey);
        System.out.println("Decrypted:" + getEncodedString(decryptedText));

        Assertions.assertEquals(plainText, new String(decryptedText));
    }

    @Test
    public void testKeyPairs() throws Exception {
        AsymmetricRSAService asymmetricRSAService = new AsymmetricRSAService();
        KeyPair keyPair = asymmetricRSAService.getRSAKeys();
        Assertions.assertNotNull(keyPair);
        Assertions.assertNotNull(keyPair.getPrivate());
        Assertions.assertNotNull(keyPair.getPublic());
        Assertions.assertTrue(keyPair.getPrivate().toString().length() >
                keyPair.getPublic().toString().length());
    }

    private String getEncodedString(byte[] toBeEncoded) {
        return Base64.getEncoder().encodeToString(toBeEncoded);
    }
}
