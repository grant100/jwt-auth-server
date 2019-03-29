package ms.auth.poc.controllers;


import com.auth0.jwt.algorithms.Algorithm;

import ms.auth.poc.WebSecurity;
import ms.auth.poc.security.ClaimConstants;
import ms.auth.poc.security.KeyProperties;
import ms.auth.poc.security.KeyService;
import ms.auth.poc.security.TokenProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.io.FileInputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

@RestController
public class AuthenticationController {
    private KeyProperties keyProperties;
    private KeyService keyService;
    private TokenProperties tokenProperties;

    @Autowired
    public AuthenticationController(KeyProperties keyProperties, KeyService keyService, TokenProperties tokenProperties) {
        this.keyProperties = keyProperties;
        this.keyService = keyService;
        this.tokenProperties = tokenProperties;
    }

    @RequestMapping(value = WebSecurity.ID_TOKEN_ENDPOINT, method = RequestMethod.POST)
    public Map authenticate(){
        return Collections.singletonMap("success",true);
    }

    @RequestMapping(value = WebSecurity.CC_TOKEN_ENDPOINT, method = RequestMethod.POST)
    public String idToken(Authentication authentication) {
        String token = null;
        String[] claims = null;

        if (authentication != null) {
            List<GrantedAuthority >authorities = new ArrayList<>(authentication.getAuthorities());
            if (!authorities.isEmpty()) {
                claims = new String[authorities.size()];
                for(int i = 0; i<authorities.size(); i++){
                    claims[i] = authorities.get(i).getAuthority();
                }
            }
        }

        try {
            token = generate(authentication.getName(), tokenProperties.getAuthnServerIssuer(), claims);
        } catch (Exception e) {
            // TODO 5? Error Handling Response?
        }

        return token;
    }

    private String generate(String subject, String issuer, String[] claims) throws Exception {
        //logger.debug("Creating token for subject {}", subject);
        Calendar now = Calendar.getInstance();
        long time = now.getTimeInMillis();
        Date expiry = new Date(time + (1800 * 1000));
        KeyPair keyPair = keyService.getKeyPair();
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        String token = com.auth0.jwt.JWT
                .create()
                .withSubject(subject)
                .withIssuer(issuer)
                .withIssuedAt(new Date())
                .withExpiresAt(expiry)
                .withArrayClaim(ClaimConstants.AUT, claims)
                .sign(algorithm);

        return token;
    }

    @ResponseBody
    @RequestMapping(value = "/cc")
    public String cc() throws Exception{
        String token = null;
        try {
            Calendar now = Calendar.getInstance();
            long time = now.getTimeInMillis();
            Date expiry = new Date(time + (1800 * 1000));
            //Algorithm algorithm = Algorithm.HMAC256("j98Nbf765bdiwD5ngks829450ykh287f7vydhGDS1");
            KeyPair keyPair = getClientRSA();
            Algorithm algorithm = Algorithm.RSA256((RSAPublicKey)keyPair.getPublic(),(RSAPrivateKey)keyPair.getPrivate());
            token = com.auth0.jwt.JWT
                    .create()
                    .withIssuer("client.node")
                    .withIssuedAt(new Date())
                    .withAudience(tokenProperties.getAuthnServerAudience())
                    .withExpiresAt(expiry)
                    .sign(algorithm);
        } catch (Exception uee) {
            //
        }
        return token;
    }

    private KeyPair getClientRSA() throws Exception{
        String alias = "client";
        String password = keyProperties.getPassword();
        String keystorePath = keyProperties.getClientKeystorePath();

        FileInputStream is = new FileInputStream(keystorePath);

        KeyStore keystore = KeyStore.getInstance(KeyStore.getDefaultType());
        keystore.load(is, password.toCharArray());

        Key key = keystore.getKey(alias, password.toCharArray());

        KeyPair keyPair = null;
        if (key instanceof PrivateKey) {
            Certificate cert = keystore.getCertificate(alias);
            keyPair = new KeyPair((RSAPublicKey) cert.getPublicKey(), (RSAPrivateKey) key);
        }
        return keyPair;
    }
}
