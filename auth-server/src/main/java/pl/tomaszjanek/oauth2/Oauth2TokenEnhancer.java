package pl.tomaszjanek.oauth2;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import java.util.HashMap;
import java.util.List;

import static java.util.stream.Collectors.toList;

public class Oauth2TokenEnhancer extends JwtAccessTokenConverter {
    @Override
    public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
        List<String> roles = authentication.getUserAuthentication()
                .getAuthorities()
                .stream()
                .map($ -> $.getAuthority())
                .collect(toList());
        DefaultOAuth2AccessToken token = new DefaultOAuth2AccessToken(accessToken);
        HashMap<String, Object> additionalInfo = new HashMap<>(accessToken.getAdditionalInformation());
        additionalInfo.put("userRoles", roles);
        token.setAdditionalInformation(additionalInfo);
        return super.enhance(token, authentication);
    }
}
