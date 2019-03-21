package ms.auth.poc.security.tokens;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class CCAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public CCAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public CCAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}
