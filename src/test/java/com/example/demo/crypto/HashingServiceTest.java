package com.example.demo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HashingServiceTest {

    private final String toBeHashed = "I am going to be hashed";
    private final String toBeHashedWithTypo = "I am going to be hashet";
    private final String toBeHashedTwiceLength = "I am going to be hashed, I am going to be hashed ";


    @Test
    public void testHash () throws NoSuchAlgorithmException {
        HashingService hashingService = HashingService.getInstance();
        String hashedFirstTime = hashingService.getHash(toBeHashed);
        Assertions.assertNotNull(hashedFirstTime);
        System.out.println("1st time hash: "+ getEncodedString(hashedFirstTime));
        String hashedSecondTime = hashingService.getHash(toBeHashed);
        System.out.println("2nd time hash: "+ getEncodedString(hashedSecondTime));
        Assertions.assertNotNull(hashedSecondTime);
        Assertions.assertEquals(hashedFirstTime,hashedSecondTime);
    }

    @Test
    public void testPseudoRandomness() throws NoSuchAlgorithmException {
        HashingService hashingService = HashingService.getInstance();
        String hashedFirstTime = hashingService.getHash(toBeHashed);
        System.out.println("1st time hash: "+ getEncodedString(hashedFirstTime));
        Assertions.assertNotNull(hashedFirstTime);
        String hashedSecondTime = hashingService.getHash(toBeHashedWithTypo);
        System.out.println("2nd time hash: "+ getEncodedString(hashedSecondTime));
        Assertions.assertNotNull(hashedSecondTime);

        Assertions.assertNotEquals(hashedFirstTime,hashedSecondTime);
    }

    @Test
    public void testHashLength() throws NoSuchAlgorithmException {
        HashingService hashingService = HashingService.getInstance();
        String hashedFirstTime = hashingService.getHash(toBeHashed);
        Assertions.assertNotNull(hashedFirstTime);
        System.out.println("Hash size (1): "+ hashedFirstTime.length());
        String hashedSecondTime = hashingService.getHash(toBeHashedTwiceLength);
        Assertions.assertNotNull(hashedSecondTime);
        System.out.println("Hash size (2): " +hashedSecondTime.length());

        Assertions.assertEquals(hashedFirstTime.length(),hashedSecondTime.length());
        Assertions.assertNotEquals(hashedFirstTime, hashedSecondTime);
    }

    private String getEncodedString(String toBeEncoded){
        return Base64.getEncoder().encodeToString(toBeEncoded.getBytes());
    }
}
