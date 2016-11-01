package pl.tomaszjanek.oauth2;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class UserInfoEndpoint {

    @GetMapping("/userInfo")
    public Principal user(Principal user) {
        return user;
    }
}
