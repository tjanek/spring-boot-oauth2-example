package pl.tomaszjanek.oauth2;

import org.springframework.boot.context.properties.ConfigurationProperties;

import static org.springframework.util.StringUtils.hasText;

@ConfigurationProperties("security.oauth2.request")
public class Oauth2RequestSecurityProperties {

    private String scope;

    public String scope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public boolean hasScope() {
        return hasText(scope);
    }
}
