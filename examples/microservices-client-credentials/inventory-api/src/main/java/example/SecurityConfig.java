package example;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Spring turns the token's "scope" claim into SCOPE_ authorities.
        // Authorize a service on its scopes; its sub is its client_id, and a
        // client_credentials token carries no roles
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(HttpMethod.GET, "/stock/**").hasAuthority("SCOPE_inventory:read")
                .requestMatchers(HttpMethod.POST, "/reservations").hasAuthority("SCOPE_inventory:reserve")
                .anyRequest().denyAll())
            .oauth2ResourceServer(oauth2 -> oauth2.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
