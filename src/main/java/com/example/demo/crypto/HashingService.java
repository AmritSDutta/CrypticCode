package com.example.demo.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashingService {

    private static final String ALGO = "SHA-256";
    private final MessageDigest messageDigest;
    private HashingService() throws NoSuchAlgorithmException {
        messageDigest = MessageDigest.getInstance(ALGO);
    }

    public static HashingService getInstance() throws NoSuchAlgorithmException {
        return new HashingService();
    }

    public String getHash(String toBeHashed)  {
        byte[] hashedBytes = messageDigest.digest(toBeHashed.getBytes());
        return new String(hashedBytes);
    }
}
