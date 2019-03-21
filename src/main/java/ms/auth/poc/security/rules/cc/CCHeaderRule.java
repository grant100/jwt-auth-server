package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

import java.util.List;

public class CCHeaderRule implements Rule {
    private final String NONE = "none";
    private DecodedJWT clientCredential;
    private List<String> encryptionTypes;

    public CCHeaderRule(DecodedJWT clientCredential, List<String> encryptionTypes) {
        this.encryptionTypes = encryptionTypes;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        String typ = clientCredential.getType();
        String alg = clientCredential.getAlgorithm();

        if (typ == null || typ.isEmpty()) {
            throw new RuleViolationException("Missing typ header claim");
        }

        if (alg == null || alg.isEmpty()) {
            throw new RuleViolationException("Missing alg header claim");
        }

        if (alg.equals(NONE)) {
            throw new RuleViolationException("Invalid alg header claim value");
        }

        if (!encryptionTypes.contains(alg)) {
            throw new RuleViolationException("Invalid alg header claim value");
        }
    }
}
