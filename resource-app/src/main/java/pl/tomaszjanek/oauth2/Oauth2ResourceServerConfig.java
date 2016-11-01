package pl.tomaszjanek.oauth2;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.*;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.ExpressionUrlAuthorizationConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.token.ResourceServerTokenServices;
import org.springframework.util.Assert;

import java.util.*;

import static java.lang.String.format;
import static java.util.stream.Collectors.toSet;

@Configuration
@EnableResourceServer
@EnableGlobalMethodSecurity(prePostEnabled = true)
@EnableConfigurationProperties(Oauth2RequestSecurityProperties.class)
public class Oauth2ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Autowired
    private ResourceServerProperties resourceServerProperties;

    @Autowired
    private Oauth2RequestSecurityProperties requestSecurityProperties;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        ExpressionUrlAuthorizationConfigurer<HttpSecurity>.ExpressionInterceptUrlRegistry authorizeRequests
                = http.requestMatchers().antMatchers("/**").and().authorizeRequests();
        if (requestSecurityProperties.hasScope()) {
            authorizeRequests.anyRequest()
                    .access(format("#oauth2.hasScope('%s')", requestSecurityProperties.scope()));
        }
    }

    @Bean
    public ResourceServerTokenServices userInfoTokenServices() {
        return new ScopedUserInfoTokenServices(
                resourceServerProperties.getUserInfoUri(),
                resourceServerProperties.getClientId()
        );
    }

    /*
        Custom copy of
        org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices
     */
    static class ScopedUserInfoTokenServices implements ResourceServerTokenServices {

        protected final Log logger = LogFactory.getLog(getClass());

        private final String userInfoEndpointUrl;

        private final String clientId;

        private OAuth2RestOperations restTemplate;

        private String tokenType = DefaultOAuth2AccessToken.BEARER_TYPE;

        private AuthoritiesExtractor authoritiesExtractor = new FixedAuthoritiesExtractor();

        private PrincipalExtractor principalExtractor = new FixedPrincipalExtractor();

        public ScopedUserInfoTokenServices(String userInfoEndpointUrl, String clientId) {
            this.userInfoEndpointUrl = userInfoEndpointUrl;
            this.clientId = clientId;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }

        public void setRestTemplate(OAuth2RestOperations restTemplate) {
            this.restTemplate = restTemplate;
        }

        public void setAuthoritiesExtractor(AuthoritiesExtractor authoritiesExtractor) {
            Assert.notNull(authoritiesExtractor, "AuthoritiesExtractor must not be null");
            this.authoritiesExtractor = authoritiesExtractor;
        }

        public void setPrincipalExtractor(PrincipalExtractor principalExtractor) {
            Assert.notNull(principalExtractor, "PrincipalExtractor must not be null");
            this.principalExtractor = principalExtractor;
        }

        @Override
        public OAuth2Authentication loadAuthentication(String accessToken)
                throws AuthenticationException, InvalidTokenException {
            Map<String, Object> map = getMap(this.userInfoEndpointUrl, accessToken);
            if (map.containsKey("error")) {
                this.logger.debug("userinfo returned error: " + map.get("error"));
                throw new InvalidTokenException(accessToken);
            }
            return extractAuthentication(map);
        }

        private OAuth2Authentication extractAuthentication(Map<String, Object> map) {
            Object principal = getPrincipal(map);
            OAuth2Request request = new OAuth2RequestBuilder(map)
                    .clientId().scopes().authorities().build();
            UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
                    principal, "N/A", request.getAuthorities());
            token.setDetails(map);
            return new OAuth2Authentication(request, token);
        }

        protected Object getPrincipal(Map<String, Object> map) {
            Object principal = this.principalExtractor.extractPrincipal(map);
            return (principal == null ? "unknown" : principal);
        }

        @Override
        public OAuth2AccessToken readAccessToken(String accessToken) {
            throw new UnsupportedOperationException("Not supported: read access token");
        }

        @SuppressWarnings({"unchecked"})
        private Map<String, Object> getMap(String path, String accessToken) {
            this.logger.info("Getting user info from: " + path);
            try {
                OAuth2RestOperations restTemplate = this.restTemplate;
                if (restTemplate == null) {
                    BaseOAuth2ProtectedResourceDetails resource = new BaseOAuth2ProtectedResourceDetails();
                    resource.setClientId(this.clientId);
                    restTemplate = new OAuth2RestTemplate(resource);
                }
                OAuth2AccessToken existingToken = restTemplate.getOAuth2ClientContext()
                        .getAccessToken();
                if (existingToken == null || !accessToken.equals(existingToken.getValue())) {
                    DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(
                            accessToken);
                    token.setTokenType(this.tokenType);
                    restTemplate.getOAuth2ClientContext().setAccessToken(token);
                }
                return restTemplate.getForEntity(path, Map.class).getBody();
            } catch (Exception ex) {
                this.logger.info("Could not fetch user details: " + ex.getClass() + ", "
                        + ex.getMessage());
                return Collections.<String, Object>singletonMap("error",
                        "Could not fetch user details");
            }
        }

        private static class OAuth2RequestBuilder {
            static final String OAUTH_2_REQUEST = "oauth2Request";
            static final String OAUTH_2_SCOPE = "scope";
            static final String OAUTH_2_CLIENT_ID = "clientId";
            static final String OAUTH_2_AUTHORITIES = "authorities";
            static final String OAUTH_2_AUTHORITY = "authority";

            Map<String, Object> request;
            String clientId;
            Set<String> scopes = new HashSet<>();
            Set<GrantedAuthority> authorities = new HashSet<>();

            OAuth2RequestBuilder(Map<String, Object> map) {
                this.request = (Map<String, Object>) map.get(OAUTH_2_REQUEST);
            }

            OAuth2RequestBuilder clientId() {
                this.clientId = (String) request.get(OAUTH_2_CLIENT_ID);
                return this;
            }

            OAuth2RequestBuilder scopes() {
                this.scopes.addAll((Collection<String>) request.get(OAUTH_2_SCOPE));
                return this;
            }

            OAuth2RequestBuilder authorities() {
                Collection<Map<String, String>> oauth2Authorities =
                        (Collection<Map<String, String>>) request.getOrDefault(OAUTH_2_AUTHORITIES, new ArrayList<>());
                Set<GrantedAuthority> grantedAuthorities = oauth2Authorities.stream()
                        .filter($ -> $.containsKey(OAUTH_2_AUTHORITY))
                        .map($ -> asGrantedAuthority($.get(OAUTH_2_AUTHORITY)))
                        .collect(toSet());
                this.authorities.addAll(grantedAuthorities);
                return this;
            }

            GrantedAuthority asGrantedAuthority(String authority) {
                return () -> authority;
            }

            OAuth2Request build() {
                return new OAuth2Request(null, this.clientId, new HashSet<>(this.authorities), true, new HashSet<>(this.scopes),
                        null, null, null, null);
            }
        }

    }
}
