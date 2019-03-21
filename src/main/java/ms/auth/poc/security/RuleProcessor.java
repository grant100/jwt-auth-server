package ms.auth.poc.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.rules.Rule;
import ms.auth.poc.security.rules.cc.CCHeaderRule;
import ms.auth.poc.security.rules.cc.CCPayloadRule;
import ms.auth.poc.security.rules.cc.CCSignatureRule;
import ms.auth.poc.security.rules.id.IDHeaderRule;
import ms.auth.poc.security.rules.id.IDPayloadRule;
import ms.auth.poc.security.rules.id.IDSignatureRule;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@Service
public class RuleProcessor {

    private KeyService keyService;
    private KeyManager keyManager;
    private TokenProperties tokenProperties;

    @Autowired
    public RuleProcessor(KeyService keyService, KeyManager keyManager, TokenProperties tokenProperties) {
        this.keyService = keyService;
        this.keyManager = keyManager;
        this.tokenProperties = tokenProperties;
    }

    public void runClientCredentialRules(DecodedJWT clientCredential) throws Exception {
        List<Rule> rules = setupClientCredentialRules(clientCredential);
        execute(rules);
    }

    public void runIDTokenRules(DecodedJWT clientCredential) throws Exception {
        List<Rule> rules = setupIDTokenRules(clientCredential);
        execute(rules);
    }

    private List<Rule> setupClientCredentialRules(DecodedJWT clientCredential) throws Exception {
        final String issuer = clientCredential.getIssuer();
        Set<String> issuers = keyManager.getIssuers(issuer);
        String audience = tokenProperties.getAuthnServerAudience();

        Algorithm algorithm = Algorithm.HMAC256(keyManager.findKey(issuer));
        CCHeaderRule headerRule = new CCHeaderRule(clientCredential, Arrays.asList("HS256"));
        CCPayloadRule payloadRule = new CCPayloadRule(clientCredential, issuers);
        CCSignatureRule signatureRule = new CCSignatureRule(clientCredential, algorithm, audience);
        return Arrays.asList(headerRule, payloadRule, signatureRule);
    }


    private List<Rule> setupIDTokenRules(DecodedJWT idToken) throws Exception {
        String issuer = tokenProperties.getAuthnServerIssuer();
        Set<String> subjects = keyManager.getIssuers(issuer);
        KeyPair keyPair = keyService.getKeyPair();
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());

        IDHeaderRule headerRule = new IDHeaderRule(idToken);
        IDPayloadRule payloadRule = new IDPayloadRule(idToken, issuer, subjects);
        IDSignatureRule signatureRule = new IDSignatureRule(idToken, algorithm, issuer);
        return Arrays.asList(headerRule, payloadRule, signatureRule);
    }

    private void execute(List<Rule> rules) {
        for (Rule rule : rules) {
            rule.execute();
        }
    }
}
