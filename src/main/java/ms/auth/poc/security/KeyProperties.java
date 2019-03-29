package ms.auth.poc.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class KeyProperties {
    @Value("${key.ssl.alias}")
    private String alias;

    @Value("${key.ssl.password}")
    private String password;

    @Value("${key.ssl.keystore.path}")
    private String keystorePath;

    @Value("${key.ssl.client.keystore.path}")
    private String clientKeystorePath;

    public String getAlias() {
        return alias;
    }

    public String getPassword() {
        return password;
    }

    public String getKeystorePath() {
        return keystorePath;
    }

    public String getClientKeystorePath() {
        return clientKeystorePath;
    }
}
