package ms.auth.poc.security;

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
import org.springframework.security.core.userdetails.User;


public class IDAuthenticationProvider  implements AuthenticationProvider {
    private static final Logger logger = LoggerFactory.getLogger(IDAuthenticationProvider.class);

    @Autowired
    private RuleProcessor ruleProcessor;


    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {

            String token = authentication.getCredentials().toString();
            logger.info("Attempting ID Token authentication");

            DecodedJWT idToken = com.auth0.jwt.JWT.decode(token);

            String issuer = idToken.getIssuer();
            String subject = idToken.getSubject();
            logger.info("Received JWT from issuer {} with subject {}", issuer, subject);

            ruleProcessor.runIDTokenRules(idToken);
            logger.info("Validated JWT signature and expiry for issuer {} and subject {}", issuer, subject);

            // Client provided a valid token
            User user = new User(issuer, authentication.getCredentials().toString(), true, true, true, true, null);

            // return a trusted token
            return new UsernamePasswordAuthenticationToken(user, token, null);

            // Authentication failed
        } catch (InvalidClaimException ice) {
            logger.error("ID Token JWT claims are invalid", ice);
            throw ice;
        } catch (JWTVerificationException jwtve) {
            logger.error("ID Token JWT verification failed", jwtve);
            throw jwtve;
        } catch (Exception e) {
            logger.error("Failed to authorize JWT", e);
            throw new BadCredentialsException("Failed to authenticate ID Token",e);
        }
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return IDAuthenticationProvider.class.isAssignableFrom(authentication);
    }
}