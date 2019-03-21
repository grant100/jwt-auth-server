package ms.auth.poc.security.tokens;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.security.auth.Subject;
import java.util.Collection;

public class IDAuthenticationToken extends UsernamePasswordAuthenticationToken {
    public IDAuthenticationToken(Object principal, Object credentials) {
        super(principal, credentials);
    }

    public IDAuthenticationToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities) {
        super(principal, credentials, authorities);
    }

    @Override
    public boolean implies(Subject subject) {
        return false;
    }
}