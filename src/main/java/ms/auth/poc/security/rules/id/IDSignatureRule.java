package ms.auth.poc.security.rules.id;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import ms.auth.poc.security.rules.Rule;

public class IDSignatureRule implements Rule {
    private DecodedJWT idToken;
    private String issuer;
    private Algorithm algorithm;

    public IDSignatureRule(DecodedJWT idToken, Algorithm algorithm, String issuer){
        this.idToken = idToken;
        this.issuer = issuer;
        this.algorithm = algorithm;
    }
    @Override
    public void execute() throws RuleViolationException {
        String signature = idToken.getSignature();

        if (signature == null || signature.isEmpty()) {
            throw new RuleViolationException("Missing ID Token signature");
        }

        try{
            // verify signature
            JWTVerifier verifier = com.auth0.jwt.JWT.require(algorithm)
                    .acceptExpiresAt(5) // 5 second leeway
                    .withIssuer(issuer)
                    .build();

            verifier.verify(idToken.getToken());
        }catch( JWTVerificationException jwtv){
            throw new RuleViolationException("ID Token Verification failed", jwtv);
        }
    }
}
