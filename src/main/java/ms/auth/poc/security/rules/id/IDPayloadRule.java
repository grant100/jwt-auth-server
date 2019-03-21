package ms.auth.poc.security.rules.id;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.ClaimConstants;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

import java.util.Date;
import java.util.List;
import java.util.Set;

public class IDPayloadRule implements Rule {
    private DecodedJWT idToken;
    private Set<String> subjects;
    private String authnServerIssuer;


    public IDPayloadRule(DecodedJWT idToken, String authnServerIssuer, Set<String> subjects) {
        this.idToken = idToken;
        this.subjects = subjects;
        this.authnServerIssuer = authnServerIssuer;
    }

    @Override
    public void execute() throws RuleViolationException {
        Date iat = idToken.getIssuedAt();
        Date exp = idToken.getExpiresAt();
        String iss = idToken.getIssuer();
        String sub = idToken.getSubject();
        List<String> aut = idToken.getClaim(ClaimConstants.AUT).asList(String.class);

        if (iat == null) {
            throw new RuleViolationException("Missing ID Token payload iat");
        }

        if (exp == null) {
            throw new RuleViolationException("Missing ID Token payload exp");
        }

        if (iss == null || iss.isEmpty()) {
            throw new RuleViolationException("Missing ID Token payload iss");
        }

        if (!iss.equals(authnServerIssuer)) {
            throw new RuleViolationException("Invalid ID Token payload iss value");
        }

        if (sub == null || sub.isEmpty()) {
            throw new RuleViolationException("Missing ID Token payload sub");
        }

        if (!subjects.contains(sub)) {
            throw new RuleViolationException("Invalid ID Token payload sub");
        }

        if (aut == null || aut.isEmpty()) {
            throw new RuleViolationException("MIssing ID Token payload aut");
        }
    }
}
