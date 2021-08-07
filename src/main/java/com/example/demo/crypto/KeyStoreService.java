package com.example.demo.crypto;

import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;

public class KeyStoreService {

    private static final  String KEY_STORE_TYPE = "PKCS12"; //Plain DES is not supported
    private static final  String FILE_NAME = "secret_storage.ks";
    private final KeyStore keyStore;
    private final char[] keyPassword;
    private final KeyStore.ProtectionParameter entryPassword;
    private final File storageFile;

    private KeyStoreService(final String password, final String dir) throws KeyStoreException, CertificateException,
            IOException, NoSuchAlgorithmException {
        this.keyStore = KeyStore.getInstance(KEY_STORE_TYPE);
        this.keyPassword = password.toCharArray();
        this.entryPassword = new KeyStore.PasswordProtection(keyPassword);
        this.storageFile = new File(dir, FILE_NAME);
        this.keyStore.load(null, keyPassword);

    }

    public static KeyStoreService getInstance(final String password, final String directoryPath) throws
            KeyStoreException, CertificateException, IOException, NoSuchAlgorithmException {
        return new KeyStoreService(password, directoryPath);
    }

    public void putKey(final String alias, final SecretKey secretKey) throws KeyStoreException {
        KeyStore.SecretKeyEntry secretKeyEntry = new KeyStore.SecretKeyEntry(secretKey);
        getKeyStore().setEntry(alias, secretKeyEntry, getEntryPassword());
    }

    public SecretKey getKey(final String alias) throws UnrecoverableEntryException, NoSuchAlgorithmException,
            KeyStoreException {
        return (SecretKey) getKeyStore().getKey(alias, getKeyPassword().toCharArray());
    }

    public void storeSecretsPersistently() throws IOException,  CertificateException,
            KeyStoreException, NoSuchAlgorithmException {
        try (FileOutputStream fos = new FileOutputStream(getStorageFile())) {
            getKeyStore().store(fos, getKeyPassword().toCharArray());
        }
    }

    public void loadSecretsFromPersistentStorage() throws IOException,  CertificateException, NoSuchAlgorithmException {
        try (FileInputStream fin = new FileInputStream(getStorageFile())) {
            getKeyStore().load(fin, getKeyPassword().toCharArray());
        }

    }


    public String getKeyStoreType() {
        return KEY_STORE_TYPE;
    }

    private KeyStore getKeyStore() {
        return this.keyStore;
    }

    public String getKeyPassword() {
        return new String(this.keyPassword);
    }

    private KeyStore.ProtectionParameter getEntryPassword() {
        return this.entryPassword;
    }

    public File getStorageFile() {
        return storageFile;
    }
}
