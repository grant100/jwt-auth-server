package ms.auth.poc.security;

import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.exceptions.RuleViolationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.List;

@Service
public class RuleProcessor {

    private KeyManager keyManager;

    @Autowired
    public RuleProcessor(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void processRules(DecodedJWT clientCredential){
        verifyClientCredentialProperties(clientCredential);
        isKnownIssuer(clientCredential.getIssuer());
    }
    public void verifyClientCredentialProperties(DecodedJWT clientCredential) {
        verifyHeader(clientCredential);
        verifyPayload(clientCredential);
    }

    public void verifyHeader(DecodedJWT clientCredential) {
        String typ = clientCredential.getType();
        String alg = clientCredential.getAlgorithm();

        if (typ == null || typ.isEmpty()) {
            throw new RuleViolationException("Missing typ header claim");
        }

        if (alg == null || alg.isEmpty()) {
            throw new RuleViolationException("Missing alg header claim");
        }
    }

    public void verifyPayload(DecodedJWT clientCredential) {

        Date iat = clientCredential.getIssuedAt();
        Date exp = clientCredential.getExpiresAt();

        String iss = clientCredential.getIssuer();
        String sub = clientCredential.getSubject();
        List<String> aud = clientCredential.getAudience();

        if (iat == null) {
            throw new RuleViolationException("Missing iat claim");
        }

        if (exp == null) {
            throw new RuleViolationException("Missing exp claim");
        }

        if (iss == null || iss.isEmpty()) {
            throw new RuleViolationException("Missing iss claim");
        }

        if(aud != null){
            if(aud.isEmpty()){
                throw new RuleViolationException("Missing aud claim");
            }
        }
    }

    public void isKnownIssuer(String issuer){
        if(!keyManager.isKnownIssuer(issuer)){
            throw new RuleViolationException("Unknown issuer");
        }
    }

    public void isKnownAudience(List<String> audiences){
        /*if(!keyManager.isKnownIssuer(issuer)){
            throw new RuleViolationException("Unknown issuer");
        }*/
    }

}
