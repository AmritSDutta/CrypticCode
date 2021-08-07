package com.example.demo.crypto;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

public class KeyStoreServiceTest {

      private final String secret = "secret123";
      private final String TEST_ALIAS = "TEST_ALIAS";
      private final String STORAGE_DIR = "D:\\KeyStorage";
      private final String KEYSTORE_TYPE = "PKCS12";

      @Test
      public void testKeyStoreInstance() throws CertificateException, KeyStoreException,
                                                                        IOException, NoSuchAlgorithmException {
          KeyStoreService keyStoreServiceIns = KeyStoreService.getInstance(secret, "D:\\KeyStorage");
          Assertions.assertNotNull(keyStoreServiceIns);
          Assertions.assertEquals(secret, keyStoreServiceIns.getKeyPassword());
          Assertions.assertEquals(KEYSTORE_TYPE, keyStoreServiceIns.getKeyStoreType());

      }

    @Test
    public void testSaveAndRetrieve() throws CertificateException, KeyStoreException,
            IOException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStoreService keyStoreServiceIns = KeyStoreService.getInstance(secret, STORAGE_DIR);
        SecretKey keyToBeStored = getKeySimple();
        Assertions.assertNotNull(keyToBeStored);

        keyStoreServiceIns.putKey(TEST_ALIAS, keyToBeStored);
        SecretKey retrievedKey = keyStoreServiceIns.getKey(TEST_ALIAS);
        Assertions.assertEquals(keyToBeStored, retrievedKey);
    }

    @Test
    public void testSaveStoreLoadAndRetrieve() throws CertificateException, KeyStoreException,
            IOException, NoSuchAlgorithmException, UnrecoverableEntryException {

        // key to be saved.
        SecretKey keyToBeStored = getKeySimple();

        // Create , save and store
        KeyStoreService keyStoreServiceStoreIns = KeyStoreService.getInstance(secret, STORAGE_DIR);
        Assertions.assertNotNull(keyToBeStored);
        keyStoreServiceStoreIns.putKey(TEST_ALIAS, keyToBeStored);
        keyStoreServiceStoreIns.storeSecretsPersistently();

        //Load and Retrieve, must use same dir , filename controlled by Service instance
        KeyStoreService keyStoreServiceLoadIns = KeyStoreService.getInstance(secret, STORAGE_DIR );
        keyStoreServiceLoadIns.loadSecretsFromPersistentStorage();
        SecretKey retrievedKey = keyStoreServiceLoadIns.getKey(TEST_ALIAS);
        Assertions.assertEquals(keyToBeStored, retrievedKey);
    }

    private SecretKey getKeySimple() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance("AES").generateKey();
    }
}
