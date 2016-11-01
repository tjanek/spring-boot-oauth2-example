package pl.tomaszjanek.oauth2;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import static java.lang.String.format;

@RestController
public class ResourceEndpoint {

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping("/greeting/{name}")
    public String greeting(@PathVariable String name) {
        return format("Greeting %s!", name);
    }
}
