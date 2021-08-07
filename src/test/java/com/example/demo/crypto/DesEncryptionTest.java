package com.example.demo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

public class DesEncryptionTest {

    private final String toBeEncrypted = "amrit";

    @Test
    public void testEncryption() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        DESEncryptionService  encryptionService = new DESEncryptionService();
        SecretKey key = encryptionService.getKeySimple();
        byte[] encryptedTExt = encryptionService.encrypt(key,toBeEncrypted);
        System.out.println("Encrypted String : " + encryptedTExt);
        Assertions.assertNotNull(encryptedTExt);
    }

    @Test
    public void testDecrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        DESEncryptionService  encryptionService = new DESEncryptionService();
        SecretKey key = encryptionService.getKeySimple();
        byte[] encryptedTExt = encryptionService.encrypt(key, toBeEncrypted);
        String decryptedText = encryptionService.decrypt(key,encryptedTExt);
        Assertions.assertEquals(toBeEncrypted, decryptedText);
    }


}
