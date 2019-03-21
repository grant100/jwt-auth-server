package ms.auth.poc.security;

import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.InvalidClaimException;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
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

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class JAuthenticationProvider implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(JAuthenticationProvider.class);

    @Autowired
    private KeyManager keyManager;

    @Autowired
    private RuleProcessor ruleProcessor;

    @Autowired
    private AuthorityManager authorityManager;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {

            String token = authentication.getCredentials().toString();
            logger.info("Attempting JWT authentication");

            DecodedJWT clientCredential = com.auth0.jwt.JWT.decode(token);

            String issuer = jwt.getIssuer();
            String subject = jwt.getSubject();
            logger.info("Received JWT from issuer {} with subject {}", issuer, subject);


            // verify token header e.g. immediately invalidate (alg=none) tokens
            if (!verifyHeader(jwt)) {
                throw new InvalidClaimException("Invalid JWT Header, header does not meet contract");
            }
            logger.info("Validated JWT header contract for issuer {} and subject {}", issuer, subject);


            // verify signature
            Algorithm algorithm = Algorithm.HMAC256(keyManager.findKey(issuer));
            JWTVerifier verifier = com.auth0.jwt.JWT.require(algorithm)
                    .acceptExpiresAt(5) // 5 second leeway
                    .withIssuer(issuer)
                    .withAudience(SecurityContract.ID_TOKEN)
                    .build();

            verifier.verify(token);

            logger.info("Validated JWT signature and expiry for issuer {} and subject {}", issuer, subject);

            Collection<? extends GrantedAuthority> authorities = getAuthorities(issuer);

            // Client provided a valid token
            User user = new User(issuer, authentication.getCredentials().toString(), true, true, true, true, authorities);

            // return a trusted token
            return new UsernamePasswordAuthenticationToken(user, token, authorities);

            // Authentication failed
        } catch (InvalidClaimException ice) {
            logger.error("JWT claims are invalid", ice);
            throw ice;
        } catch (JWTVerificationException jwtve) {
            logger.error("JWT verification failed", jwtve);
            throw jwtve;
        } catch (Exception e) {
            logger.error("Failed to authorize JWT", e);
            throw new BadCredentialsException("Failed to authenticate",e);
        }
    }

    /**
     * Returns false if incoming JWT doesn't meet Algorithm or Type contract
     *
     * @param jwtToken DecodedJWT
     */
    boolean verifyHeader(DecodedJWT jwtToken) {
        if (jwtToken.getAlgorithm().equals("none")){
            return false;
        }
        return true;
    }

    Collection<? extends GrantedAuthority> getAuthorities(String issuer) throws Exception {
        List<SimpleGrantedAuthority> authorityList = new ArrayList<>();
        List<String> authorities = authorityManager.getEntitlementsByIssuer(issuer);

        for (String authority : authorities) {
            authorityList.add(new SimpleGrantedAuthority(authority));
        }
        logger.debug("Assigning authorities(s) {} for {}", authorities, issuer);
        return authorityList;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}