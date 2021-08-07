package com.example.demo.bouncycastle;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class BCEncryptionServiceTest {

    private final String toBeEncrypted = "Nice to see you there";


    @Test
    public void testEncryption() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        BCEncryptionService encryptionService = BCEncryptionService.getInstance();
        SecretKey key = encryptionService.getKeySimple();
        byte[] encryptedTExt = encryptionService.encrypt(key,toBeEncrypted);
        System.out.println("Encrypted String : " + encryptedTExt);
        Assertions.assertNotNull(encryptedTExt);
    }

    @Test
    public void testDecrypt() throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException,
            BadPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchProviderException {
        BCEncryptionService  encryptionService = BCEncryptionService.getInstance();
        SecretKey key = encryptionService.getKeySimple();
        byte[] encryptedTExt = encryptionService.encrypt(key, toBeEncrypted);
        String decryptedText = encryptionService.decrypt(key,encryptedTExt);
        System.out.println("Decrypted String : " + decryptedText);
        Assertions.assertEquals(toBeEncrypted, decryptedText);
    }


}
