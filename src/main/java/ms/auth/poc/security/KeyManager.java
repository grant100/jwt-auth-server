package ms.auth.poc.security;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@ConfigurationProperties(prefix = "keys")
public class KeyManager {

    private Map<String, String> keys;

    public void setKeys(HashMap<String, String> secrets) {
        // prevent modification of set property
        if (this.keys == null) {
            this.keys = Collections.unmodifiableMap(new HashMap<>(secrets));
        }
    }

    String findKey(String issuer) throws Exception {
        final String secret;
        if (!keys.containsKey(issuer)) {
            throw new Exception("Issuer does not exist");
        }
        secret = keys.get(issuer);
        if (secret == null || secret.isEmpty()) {
            throw new Exception("Key cannot be null or empty");
        }
        return secret;
    }

    boolean isKnownIssuer(String issuer) {
        return keys.containsKey(issuer);
    }
}
