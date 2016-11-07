package pl.tomaszjanek.oauth2;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SpringBootApplication
public class Oauth2ResourceApplication {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2ResourceApplication.class, args);
    }

    @Configuration
    @EnableGlobalMethodSecurity(prePostEnabled = true)
    @EnableResourceServer
    protected static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

        @Value("${jwtPublicKey}")
        String jwtPublicKey;

        @Bean
        public TokenStore tokenStore() {
            JwtTokenStore tokenStore = new JwtTokenStore(tokenEnhancer());
            return tokenStore;
        }

        @Bean
        public JwtAccessTokenConverter tokenEnhancer() {
            JwtAccessTokenConverter tokenEnhancer = new JwtTokenEnhancer();
            tokenEnhancer.setVerifierKey(jwtPublicKey);
            return tokenEnhancer;
        }

        @Override
        public void configure(HttpSecurity http) throws Exception {
            http
                .authorizeRequests().anyRequest().authenticated()
                .and()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.NEVER)
            ;
        }
    }
}
