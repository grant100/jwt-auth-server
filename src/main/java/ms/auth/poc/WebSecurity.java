package ms.auth.poc;

import ms.auth.poc.security.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.util.ArrayList;
import java.util.List;

@EnableWebSecurity(debug = false)
public class WebSecurity {

    public static final String CC_TOKEN_ENDPOINT = "/token";
    private static final String ID_TOKEN_ENDPOINT = "/authenticate";


    @Configuration
    @Order(1)
    public static class AuthenticationConfigurer extends WebSecurityConfigurerAdapter {

        public AuthenticationConfigurer() {
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .cors().and().csrf().disable().rememberMe().disable().logout().disable().formLogin().disable().httpBasic().disable()
                    .exceptionHandling()
                    .defaultAuthenticationEntryPointFor(ccAuthenticationEntryPoint(), new AntPathRequestMatcher(CC_TOKEN_ENDPOINT))
                    .defaultAuthenticationEntryPointFor(idAuthenticationEntryPoint(), new AntPathRequestMatcher(ID_TOKEN_ENDPOINT))
                    .and()
                    .addFilterAt(authFilters(), BasicAuthenticationFilter.class)
                    .authorizeRequests()
                    .antMatchers(CC_TOKEN_ENDPOINT).anonymous()
                    .antMatchers(ID_TOKEN_ENDPOINT).anonymous()
                    .anyRequest().denyAll() // any url that has not been matched is denied by default
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            ;
        }

        @Bean
        public FilterChainProxy authFilters() throws Exception {
            List<SecurityFilterChain> chains = new ArrayList<>();
            chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(CC_TOKEN_ENDPOINT), ccAuthenticationFilter()));
            chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(ID_TOKEN_ENDPOINT), idAuthenticationFilter()));
            return new FilterChainProxy(chains);
        }

        // Configure AuthenticationManager to use JWTAuthenticationProvider implementation
        @Override
        public void configure(AuthenticationManagerBuilder auth) {
            auth.authenticationProvider(ccAuthenticationProvider());
            auth.authenticationProvider(ccAuthenticationProvider());
        }

        @Bean
        CCAuthenticationProvider ccAuthenticationProvider() {
            return new CCAuthenticationProvider();
        }

        @Bean
        IDAuthenticationProvider idAuthenticationProvider() {
            return new IDAuthenticationProvider();
        }

        @Bean
        KeyManager keyManager() {
            return new KeyManager();
        }

        @Bean
        AuthorityManager authorityManager() {
            return new AuthorityManager();
        }

        @Bean
        CCAuthenticationFilter ccAuthenticationFilter() throws Exception {
            return new CCAuthenticationFilter(authenticationManager());
        }

        @Bean
        IDAuthenticationFilter idAuthenticationFilter() throws Exception {
            return new IDAuthenticationFilter(authenticationManager());
        }

        @Bean
        CCAuthenticationEntryPoint ccAuthenticationEntryPoint() {
            return new CCAuthenticationEntryPoint();
        }

        @Bean
        IDAuthenticationEntryPoint idAuthenticationEntryPoint() {
            return new IDAuthenticationEntryPoint();
        }
    }

}
