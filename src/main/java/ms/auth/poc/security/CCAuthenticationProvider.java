package ms.auth.poc.security;

import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import ms.auth.poc.security.tokens.CCAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;

public class CCAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(CCAuthenticationProvider.class);

    @Autowired
    private RuleProcessor ruleProcessor;

    @Autowired
    private AuthorityManager authorityManager;

    @Autowired
    private KeyService keyService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {

            String token = authentication.getCredentials().toString();
            logger.info("Attempting Client Credential authentication");

            DecodedJWT clientCredential = com.auth0.jwt.JWT.decode(token);

            String issuer = clientCredential.getIssuer();
            logger.info("Received JWT from issuer {}", issuer);

            ruleProcessor.runClientCredentialRules(clientCredential);
            logger.info("Validated JWT signature and expiry for issuer {}", issuer);

            Collection<? extends GrantedAuthority> authorities = getAuthorities(issuer);

            // Client provided a valid token
            User user = new User(issuer, authentication.getCredentials().toString(), true, true, true, true, authorities);

            // return a trusted token
            return new UsernamePasswordAuthenticationToken(user, token, authorities);

            // Authentication failed
        } catch (InvalidClaimException ice) {
            logger.error("Client Credential JWT claims are invalid", ice);
            throw ice;
        } catch (JWTVerificationException jwtve) {
            logger.error("Client Credential JWT verification failed", jwtve);
            throw jwtve;
        } catch (Exception e) {
            logger.error("Failed to authorize JWT", e);
            throw new BadCredentialsException("Failed to authenticate Client Credential",e);
        }
    }


    @Override
    public boolean supports(Class<?> authentication) {
        return CCAuthenticationToken.class.isAssignableFrom(authentication);
    }

    /**
     * Retrieve entitlements for authenticated tokens/client apps.
     *
     * @param issuer
     * @return Collection of GrantedAuthority
     */
    Collection<? extends GrantedAuthority> getAuthorities(String issuer) throws Exception {
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        List<String> authorities = authorityManager.getEntitlementsByIssuer(issuer);

        for (String authority : authorities) {
            authorityList.add(new SimpleGrantedAuthority(authority));
        }
        logger.debug("Assigning entitlement(s) {} for {}", authorities, issuer);
        return authorityList;
    }

}