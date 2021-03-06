package ms.auth.poc.security.rules.cc;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

public class CCSignatureRule implements Rule {
    private String audience;
    private Algorithm algorithm;
    private DecodedJWT clientCredential;

    public CCSignatureRule(DecodedJWT clientCredential, Algorithm algorithm, String audience) {
        this.audience = audience;
        this.algorithm = algorithm;
        this.clientCredential = clientCredential;
    }

    @Override
    public void execute() throws RuleViolationException {
        String signature = clientCredential.getSignature();

        if (signature == null || signature.isEmpty()) {
            throw new RuleViolationException("Missing Client Credential signature");
        }

        try{
            // verify signature
            JWTVerifier verifier = com.auth0.jwt.JWT.require(algorithm)
                    .acceptExpiresAt(5) // 5 second leeway
                    .withAudience(audience)
                    .build();

            verifier.verify(clientCredential.getToken());
        }catch( JWTVerificationException jwtv){
            throw new RuleViolationException("Client Credential Verification failed", jwtv);
        }

    }
}