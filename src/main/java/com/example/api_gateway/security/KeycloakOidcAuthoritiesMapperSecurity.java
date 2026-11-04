package com.example.api_gateway.security;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.Set;

public class KeycloakOidcAuthoritiesMapperSecurity
        implements GrantedAuthoritiesMapper {

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(
            Collection<? extends GrantedAuthority> authorities) {

        Set<GrantedAuthority> mappedAuthorities =
                new LinkedHashSet<>(authorities);

        authorities.stream()
                .filter(OidcUserAuthority.class::isInstance)
                .map(OidcUserAuthority.class::cast)
                .map(oidcAuthority ->
                        oidcAuthority.getIdToken().getClaims()
                                .get("realm_access"))
                .map(KeycloakRealmRolesSecurity::extract)
                .forEach(mappedAuthorities::addAll);

        return mappedAuthorities;
    }
}