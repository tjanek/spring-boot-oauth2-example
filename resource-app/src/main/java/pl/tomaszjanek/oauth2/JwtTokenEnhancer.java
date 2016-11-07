package pl.tomaszjanek.oauth2;

import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.HashMap;
import java.util.Map;

public class JwtTokenEnhancer extends JwtAccessTokenConverter {

    @Override
    public OAuth2Authentication extractAuthentication(Map<String, ?> map) {
        OAuth2Authentication oAuth2Authentication = super.extractAuthentication(map);
        Map<String, Object> details = new HashMap<>();
        details.put("userRoles", map.get("userRoles"));
        oAuth2Authentication.setDetails(details);
        return oAuth2Authentication;
    }
}
