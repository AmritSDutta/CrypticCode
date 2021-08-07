package com.example.demo.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.stream.Stream;

public class TestJCADetails {


    @Test
    public void testMaxAllowedKeyLength () throws NoSuchAlgorithmException {
        //if following assertion fails, use - Security.setProperty("crypto.policy", "unlimited");
        Assertions.assertTrue(javax.crypto.Cipher.getMaxAllowedKeyLength("AES") >= 2147483647);
    }

    @Test
    public void testProvidersDetails() {
        Provider[] providers = Security.getProviders();
        System.out.println("No. of Providers :"+ providers.length);
        System.out.println("Providers Details :");
        Stream.of(providers).forEach(provider -> {
            System.out.print(provider.getName());
            System.out.println(", "+ provider.getInfo());
            //provider.getServices().stream().forEach(System.out::println);
        });
    }

    @Test
    public void testAdditionalProvidersDetails() {
        int noOfProviders =  Security.getProviders().length;
        Security.insertProviderAt(new BouncyCastleProvider(),Security.getProviders().length+1);
        Provider[] providers = Security.getProviders();
        Assertions.assertTrue(providers.length > noOfProviders);
        //providers[Security.getProviders().length-1].getServices().stream().forEach(serv -> System.out.print("\t\t"+ serv));
        System.out.println("No of services in Newly added provider : "+providers[Security.getProviders().length-1]
                                                                                        .getServices().size());
    }
}
