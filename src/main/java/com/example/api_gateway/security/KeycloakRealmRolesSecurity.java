package com.example.api_gateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;

public final class KeycloakRealmRolesSecurity {

    private static final Set<String> APPLICATION_ROLES =
            Set.of("USER", "ADMIN");

    private KeycloakRealmRolesSecurity() {
    }

    public static List<GrantedAuthority> extract(Object realmAccessClaim) {
        if (!(realmAccessClaim instanceof Map<?, ?> realmAccess)) {
            return List.of();
        }

        Object rolesClaim = realmAccess.get("roles");

        if (!(rolesClaim instanceof Collection<?> roles)) {
            return List.of();
        }

        return roles.stream()
                .filter(String.class::isInstance)
                .map(String.class::cast)
                .filter(APPLICATION_ROLES::contains)
                .map(role -> (GrantedAuthority)
                        new SimpleGrantedAuthority("ROLE_" + role))
                .toList();
    }
}