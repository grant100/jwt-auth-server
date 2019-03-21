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
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity(debug = false)
public class WebSecurity {

    @Configuration
    @Order(1)
    public static class AuthenticationConfigurer extends WebSecurityConfigurerAdapter {

        public AuthenticationConfigurer() {
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .cors().and().csrf().disable().rememberMe().disable().logout().disable().formLogin().disable().httpBasic().disable()
                    .authorizeRequests()
                    .antMatchers("/id-token").anonymous()
                    .anyRequest().denyAll() // any url that has not been matched is denied by default
                    .and()
                    .addFilterAt(new AuthenticationFilter(authenticationManager()), BasicAuthenticationFilter.class)
                    .exceptionHandling().authenticationEntryPoint(new AuthenticationEntryPoint())
                    .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            ;
        }

        // Configure AuthenticationManager to use JWTAuthenticationProvider implementation
        @Override
        public void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.authenticationProvider(jAuthenticationProvider());
        }

        @Bean
        JAuthenticationProvider jAuthenticationProvider(){
            return new JAuthenticationProvider();
        }

        @Bean
        KeyManager keyManager(){
            return new KeyManager();
        }

        @Bean
        AuthorityManager authorityManager(){
            return new AuthorityManager();
        }
    }

}
