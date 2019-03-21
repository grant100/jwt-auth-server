package ms.auth.poc.security.rules.id;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

public class IDHeaderRule implements Rule {
    private final String NONE = "none";
    private final String ALG = "RS256";
    private DecodedJWT idToken;

    public IDHeaderRule(DecodedJWT idToken) {
        this.idToken = idToken;
    }

    @Override
    public void execute() throws RuleViolationException {

        String typ = idToken.getType();
        String alg = idToken.getAlgorithm();

        if (typ == null || typ.isEmpty()) {
            throw new RuleViolationException("Missing ID Token typ header");
        }

        if (alg == null || alg.isEmpty()) {
            throw new RuleViolationException("Missing ID Token alg header");
        }

        if (alg.equals(NONE)) {
            throw new RuleViolationException("Invalid ID Token alg header value");
        }

        if (alg.equals(ALG)) {
            throw new RuleViolationException("Invalid ID Token alg header value");
        }
    }
}
