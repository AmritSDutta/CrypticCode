package com.example.demo.crypto;

import javax.crypto.SecretKey;
import javax.crypto.KeyGenerator;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

public class DESEncryptionService {
    private static final String ALGO = "DES";
    private static final String ALGO_FOR_ENCRYPTION = "DES/CBC/PKCS5Padding";
    private static final int  MAX_IV_LENGTH = 8;
    private byte[] IV;

    public SecretKey getKeySimple() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(ALGO).generateKey();
    }

    public byte[] encrypt(SecretKey key, String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

        this.IV = new byte[MAX_IV_LENGTH];
        new SecureRandom().nextBytes(IV);
        Cipher cipher = Cipher.getInstance(ALGO_FOR_ENCRYPTION);
        //As CBC used need an initialization vector.
        AlgorithmParameterSpec algoParamSpec = new IvParameterSpec(IV);
        cipher.init(Cipher.ENCRYPT_MODE, key, algoParamSpec);

        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }

    public String decrypt(SecretKey key, byte[] cypherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
        Cipher cipher = Cipher.getInstance(ALGO_FOR_ENCRYPTION);
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(this.IV));
        return new String(cipher.doFinal(cypherText));
    }

}
