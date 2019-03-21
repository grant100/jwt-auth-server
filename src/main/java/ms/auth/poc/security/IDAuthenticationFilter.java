package ms.auth.poc.security;

import ms.auth.poc.security.tokens.IDAuthenticationToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class IDAuthenticationFilter extends OncePerRequestFilter {
    private static final Logger logger = LoggerFactory.getLogger(IDAuthenticationFilter.class);

    private AuthenticationManager authenticationManager;

    public IDAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        String header = request.getHeader(HttpContract.AUTHORIZATION);

        if (header == null || header.isEmpty() || !header.startsWith(HttpContract.BEARER)) {
            chain.doFilter(request, response);
            return;
        }

        try {
            String jwt = header.replace(HttpContract.BEARER, "");
            Authentication authRequest = new IDAuthenticationToken(SecurityContract.ID_TOKEN, jwt);

            // delegate to AuthenticationManager to iterate AuthenticationProvider implementation(s)
            Authentication authResults = authenticationManager.authenticate(authRequest);

            // No errors, set Authentication in security context
            SecurityContextHolder.getContext().setAuthentication(authResults);
        } catch (AuthenticationException failed) {
            SecurityContextHolder.clearContext();
            logger.debug("Authentication request failed", failed);
        }

        chain.doFilter(request, response);
    }
}
