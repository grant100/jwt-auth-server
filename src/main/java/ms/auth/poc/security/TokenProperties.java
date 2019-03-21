package ms.auth.poc.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;

@Configuration
public class TokenProperties {
    @Value("${authn.server.issuer}")
    private String authnServerIssuer;

    @Value("${authn.server.audience}")
    private String authnServerAudience;

    public String getAuthnServerIssuer() {
        return authnServerIssuer;
    }

    public String getAuthnServerAudience(){
        return authnServerAudience;
    }
}
