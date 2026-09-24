package example;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HomeController {

    @GetMapping("/")
    String home(Authentication authentication) {
        var principal = (Saml2AuthenticatedPrincipal) authentication.getPrincipal();
        return "user=" + authentication.getName()
                + " authorities=" + authentication.getAuthorities().stream()
                        .map(GrantedAuthority::getAuthority).sorted().toList()
                + " attributes=" + principal.getAttributes() + "\n";
    }

    @GetMapping("/admin")
    String admin(Authentication authentication) {
        return "admin area for " + authentication.getName() + "\n";
    }
}
