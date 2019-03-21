package ms.auth.poc.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Service
public class KeyService {
    private KeyProperties keyProperties;

    @Autowired
    public KeyService(KeyProperties keyProperties) {
        this.keyProperties = keyProperties;
    }

    public KeyPair getKeyPair() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableKeyException {
        String alias = keyProperties.getAlias();
        String password = keyProperties.getPassword();
        String keystorePath = keyProperties.getKeystorePath();

        FileInputStream is = new FileInputStream(keystorePath);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password.toCharArray());

        Key key = keystore.getKey(alias, password.toCharArray());

        KeyPair keyPair = null;
        if (key instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate(alias);
            keyPair = new KeyPair((RSAPublicKey) cert.getPublicKey(), (RSAPrivateKey) key);
        }
        return keyPair;
    }
}
