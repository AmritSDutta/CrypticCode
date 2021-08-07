package com.example.demo.bouncycastle;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;

public class BCEncryptionService {

    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 16;
    public static final int GCM_TAG_LENGTH = 16;
    private static final String ALGO = "AES";
    private static final String ALGO_FOR_ENCRYPTION = "AES/GCM/NoPadding";
    private byte[] iv;

   private BCEncryptionService(){}

    public static BCEncryptionService getInstance() {
        Security.insertProviderAt(new BouncyCastleProvider(),Security.getProviders().length+1);
        return new BCEncryptionService();
    }

    public SecretKey getKeySimple() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(ALGO);
        keyGenerator.init(AES_KEY_SIZE);
        return keyGenerator.generateKey();
    }

    public byte[] encrypt(SecretKey key, String plainText) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
                                        NoSuchProviderException {

        this.iv = new byte[GCM_IV_LENGTH];
        new SecureRandom().nextBytes(iv);
        Cipher cipher = Cipher.getInstance(ALGO_FOR_ENCRYPTION, "BC");
        AlgorithmParameterSpec algoParamSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, algoParamSpec);
        System.out.println("Enc Provider : " + cipher.getProvider());
        return cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
    }


    public String decrypt(SecretKey key, byte[] cypherText) throws NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException,
                                            NoSuchProviderException {
        Cipher cipher = Cipher.getInstance(ALGO_FOR_ENCRYPTION, "BC");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv));
        System.out.println("Dec Provider : " + cipher.getProvider());
        return new String(cipher.doFinal(cypherText));
    }

    /*private AlgorithmParameterSpec getAlgorithmParameterSpec(){
        byte[] assocData = Hex.decode("10111213141516171819");
        byte[] nonce = Hex.decode("202122232425262728292a2b2c");
        return new AEADParameterSpec(nonce, 96, assocData);
    }*/
}
