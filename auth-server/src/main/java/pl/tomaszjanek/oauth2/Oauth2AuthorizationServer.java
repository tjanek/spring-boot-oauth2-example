package pl.tomaszjanek.oauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@SpringBootApplication
public class Oauth2AuthorizationServer {

    public static void main(String[] args) {
        SpringApplication.run(Oauth2AuthorizationServer.class, args);
    }

    @Configuration
    @EnableWebSecurity
    protected static class SecurityConfig extends WebSecurityConfigurerAdapter {

        @Override
        @Autowired
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.inMemoryAuthentication()
                .withUser("user").password("pass")
                .roles("USER")
                .and()
                .withUser("admin").password("pass")
                .roles("USER", "ADMIN")
            ;
        }

        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                .httpBasic().disable()
                .anonymous().disable()
                .authorizeRequests().anyRequest().authenticated()
            ;
        }
    }

    @Configuration
    @EnableAuthorizationServer
    protected static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

        @Value("${config.oauth2.privateKey}")
        private String privateKey;

        @Value("${config.oauth2.publicKey}")
        private String publicKey;

        @Autowired
        private AuthenticationManager authenticationManager;

        @Bean
        public JwtAccessTokenConverter tokenEnhancer() {
            JwtAccessTokenConverter converter = new JwtAccessTokenConverter();
            converter.setSigningKey(privateKey);
            converter.setVerifierKey(publicKey);
            return converter;
        }

        @Bean
        public JwtTokenStore tokenStore() {
            return new JwtTokenStore(tokenEnhancer());
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            endpoints
                .authenticationManager(authenticationManager)
                .tokenStore(tokenStore())
                .accessTokenConverter(tokenEnhancer())
            ;
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
            clients.inMemory()
                    .withClient("web")
                    .authorities("ROLE_USER", "ROLE_ADMIN")
                    //.resourceIds("shop")
                    .scopes("read", "write")
                    .authorizedGrantTypes("password", "refresh_token")
                    .secret("pass");
        }

    }
}
