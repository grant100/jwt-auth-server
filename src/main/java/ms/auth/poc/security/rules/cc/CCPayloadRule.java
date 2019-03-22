package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

import java.util.Date;
import java.util.List;
import java.util.Set;

public class CCPayloadRule implements Rule {

    private Set<String> issuers;
    private String audience;
    private DecodedJWT clientCredential;

    public CCPayloadRule(DecodedJWT clientCredential, Set<String> issuers, String audience) {
        this.issuers = issuers;
        this.audience = audience;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        Date iat = clientCredential.getIssuedAt();
        Date exp = clientCredential.getExpiresAt();
        String iss = clientCredential.getIssuer();
        List<String> aud = clientCredential.getAudience();

        if (iat == null) {
            throw new RuleViolationException("Missing Client Credential payload iat");
        }

        if (exp == null) {
            throw new RuleViolationException("Missing Client Credential payload exp");
        }

        if (iss == null || iss.isEmpty()) {
            throw new RuleViolationException("Missing Client Credential payload iss");
        }

        if(!issuers.contains(iss)){
            throw new RuleViolationException("Invalid Client Credential payload iss value");
        }

        if(aud == null || aud.isEmpty()){
            throw new RuleViolationException("Missing Client Credential payload aud");
        }

        if(!aud.contains(audience)){
            throw new RuleViolationException("Invalid Client Credential payload aud");
        }
    }
}
