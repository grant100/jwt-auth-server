package ms.auth.poc.controllers;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import ms.auth.poc.WebSecurity;
import ms.auth.poc.security.KeyService;
import ms.auth.poc.security.TokenProperties;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.List;

@RestController
public class AuthenticationController {
    private KeyService keyService;
    private TokenProperties tokenProperties;

    @Autowired
    public AuthenticationController(KeyService keyService, TokenProperties tokenProperties) {
        this.keyService = keyService;
        this.tokenProperties = tokenProperties;
    }

    @RequestMapping(value = WebSecurity.CC_TOKEN_ENDPOINT, method = RequestMethod.GET)
    public String idToken(Authentication authentication) {
        String token = null;
        String[] claims = null;

        Collection<? extends GrantedAuthority> authorities;
        if(authentication != null){
            authorities = authentication.getAuthorities();

            if (!authorities.isEmpty()) {
                claims = (String[]) authorities.toArray();
            }
        }

        try {
            token = generate(authentication.getName(), tokenProperties.getAuthnServerIssuer(), claims);
        } catch (Exception e) {
            // 5? Error Handling Response?
        }

        return token;
    }

    private String generate(String subject, String issuer, String[] claims) throws Exception {
        //logger.debug("Creating token for subject {}", subject);
        Calendar now = Calendar.getInstance();
        long time = now.getTimeInMillis();
        Date expiry = new Date(time + (30 * 1000));
        KeyPair keyPair = keyService.getKeyPair();
        Algorithm algorithm = Algorithm.RSA256((RSAPublicKey) keyPair.getPublic(), (RSAPrivateKey) keyPair.getPrivate());
        String token = com.auth0.jwt.JWT
                .create()
                .withSubject(subject)
                .withIssuer(issuer)
                .withIssuedAt(new Date())
                .withExpiresAt(expiry)
                .withArrayClaim("aut", claims)
                .sign(algorithm);

        return token;
    }

    @RequestMapping(value = "/cc")
    public String cc(){
        String token;
        try {
            Calendar now = Calendar.getInstance();
            long time = now.getTimeInMillis();
            Date expiry = new Date(time + (timeout * 1000));
            Algorithm algorithm = Algorithm.HMAC256(secret);
            this.token = com.auth0.jwt.JWT
                    .create()
                    .withSubject(SUBJECT)
                    .withIssuer(issuer)
                    .withAudience(SecurityConstants.API_NAME)
                    .withIssuedAt(new Date())
                    .withExpiresAt(expiry)
                    .sign(algorithm);
        } catch (Exception uee) {
            throw new TokenException(uee);
        }
        return token;
    }
}
