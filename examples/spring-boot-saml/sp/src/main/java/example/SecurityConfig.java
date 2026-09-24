package example;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.schema.XSAny;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.saml2.provider.service.authentication.OpenSaml5AuthenticationProvider;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // By default a SAML login carries no role; turn the assertion's
        // "roles" attribute into ROLE_ authorities so hasRole() works
        var converter = new OpenSaml5AuthenticationProvider.ResponseAuthenticationConverter();
        converter.setGrantedAuthoritiesConverter(SecurityConfig::rolesFromAssertion);
        var provider = new OpenSaml5AuthenticationProvider();
        provider.setResponseAuthenticationConverter(converter);

        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated())
            .saml2Login(saml -> saml.authenticationManager(provider::authenticate))
            .saml2Metadata(Customizer.withDefaults());
        return http.build();
    }

    static Collection<GrantedAuthority> rolesFromAssertion(Assertion assertion) {
        List<GrantedAuthority> authorities = new ArrayList<>();
        for (AttributeStatement statement : assertion.getAttributeStatements()) {
            for (Attribute attribute : statement.getAttributes()) {
                if (!"roles".equals(attribute.getName())) {
                    continue;
                }
                for (XMLObject value : attribute.getAttributeValues()) {
                    // NanoIDP sends values without xsi:type: OpenSAML reads them as XSAny
                    String role = value instanceof XSString s ? s.getValue()
                            : value instanceof XSAny any ? any.getTextContent() : null;
                    if (role != null) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
                    }
                }
            }
        }
        return authorities;
    }
}
