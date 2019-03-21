package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

public class CCSignatureRule implements Rule {
    private Algorithm algorithm;
    private DecodedJWT clientCredential;

    public CCSignatureRule(DecodedJWT clientCredential, Algorithm algorithm) {
        this.algorithm = algorithm;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        String signature = clientCredential.getSignature();

        if (signature == null || signature.isEmpty()) {
            throw new RuleViolationException("Missing signature");
        }

        try{
            // verify signature
            JWTVerifier verifier = com.auth0.jwt.JWT.require(algorithm)
                    .acceptExpiresAt(5) // 5 second leeway
                    .withAudience("authn.server.poc")
                    .build();

            verifier.verify(clientCredential.getToken());
        }catch( JWTVerificationException jwtv){
            throw new RuleViolationException("JWT Verification failed", jwtv);
        }

    }
}