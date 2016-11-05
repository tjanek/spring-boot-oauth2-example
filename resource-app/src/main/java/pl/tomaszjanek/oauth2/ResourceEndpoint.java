package pl.tomaszjanek.oauth2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import static java.lang.String.format;

@RestController
public class ResourceEndpoint {

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/greeting")
    public String greeting() {
        return format("Greeting %s\r\n", userDetails());
    }

    private Object userDetails() {
        return SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
    }
}
