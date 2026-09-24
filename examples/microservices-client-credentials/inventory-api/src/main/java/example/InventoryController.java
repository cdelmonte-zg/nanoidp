package example;

import java.util.Map;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InventoryController {

    @GetMapping("/stock/{sku}")
    Map<String, Object> stock(@PathVariable String sku, @AuthenticationPrincipal Jwt jwt) {
        // The calling service is the token's client_id
        return Map.of("sku", sku, "available", 42, "caller", jwt.getClaimAsString("client_id"));
    }

    @PostMapping("/reservations")
    Map<String, Object> reserve(@AuthenticationPrincipal Jwt jwt) {
        return Map.of("reserved", true, "caller", jwt.getClaimAsString("client_id"));
    }
}
