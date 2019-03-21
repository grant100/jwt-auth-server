package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

import java.util.Date;
import java.util.List;
import java.util.Set;

public class CCPayloadRule implements Rule {

    private Set<String> issuers;
    private Set<String> audiences;
    private DecodedJWT clientCredential;

    public CCPayloadRule(DecodedJWT clientCredential, Set<String> issuers, Set<String> audiences) {
        this.issuers = issuers;
        this.audiences = audiences;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        Date iat = clientCredential.getIssuedAt();
        Date exp = clientCredential.getExpiresAt();

        String iss = clientCredential.getIssuer();
        List<String> aud = clientCredential.getAudience();

        if (iat == null) {
            throw new RuleViolationException("Missing payload iat claim");
        }

        if (exp == null) {
            throw new RuleViolationException("Missing payload exp claim");
        }

        if (iss == null || iss.isEmpty()) {
            throw new RuleViolationException("Missing payload iss claim");
        }

        if (aud != null) {
            if (aud.isEmpty()) {
                throw new RuleViolationException("Missing payload aud claim");
            }

            if(!audiences.contains(aud)){
                throw new RuleViolationException("Invalid payload aud claim value");
            }
        }

        if(!issuers.contains(iss)){
            throw new RuleViolationException("Invalid payload iss claim value");
        }
    }
}
