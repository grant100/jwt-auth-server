package ms.auth.poc.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.rules.Rule;
import ms.auth.poc.security.rules.cc.CCHeaderRule;
import ms.auth.poc.security.rules.cc.CCPayloadRule;
import ms.auth.poc.security.rules.cc.CCSignatureRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
public class RuleProcessor {

    private KeyManager keyManager;

    @Autowired
    public RuleProcessor(KeyManager keyManager) {
        this.keyManager = keyManager;
    }

    public void processRules(DecodedJWT clientCredential) throws Exception{
        List<Rule> rules = setup(clientCredential);
        execute(rules);
    }

    private void execute(List<Rule> rules){
        for(Rule rule : rules){
            rule.execute();;
        }
    }

    private List<Rule> setup(DecodedJWT clientCredential) throws Exception{
        final String issuer = clientCredential.getIssuer();
        Set<String> issuers = keyManager.getIssuers(issuer);
        Algorithm algorithm = Algorithm.HMAC256(keyManager.findKey(issuer));
        CCHeaderRule headerRule = new CCHeaderRule(clientCredential, Arrays.asList("HS256"));
        CCPayloadRule payloadRule = new CCPayloadRule(clientCredential, issuers, issuers);
        CCSignatureRule signatureRule = new CCSignatureRule(clientCredential, algorithm);
        return Arrays.asList(headerRule, payloadRule, signatureRule);
    }
}
