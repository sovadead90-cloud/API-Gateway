package com.example.api_gateway.config;

import com.example.api_gateway.security.KeycloakOidcAuthoritiesMapperSecurity;
import com.example.api_gateway.security.KeycloakRealmRoleConverterSecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http,
            KeycloakRealmRoleConverterSecurity jwtConverter) {

        return http
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/oauth2/**").permitAll()
                        .pathMatchers("/api/v1/admin/**").hasRole("ADMIN")
                        .pathMatchers("/api/v1/files/**")
                        .hasAnyRole("USER", "ADMIN")
                        .anyExchange().authenticated()
                )
                .oauth2Login(Customizer.withDefaults())
                .oauth2Client(Customizer.withDefaults())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt
                                .jwtAuthenticationConverter(
                                        new ReactiveJwtAuthenticationConverterAdapter(
                                                createJwtAuthenticationConverter(jwtConverter)
                                        )
                                )
                        )
                )
                .build();
    }

    private JwtAuthenticationConverter createJwtAuthenticationConverter(
            KeycloakRealmRoleConverterSecurity roleConverter) {

        JwtAuthenticationConverter converter =
                new JwtAuthenticationConverter();

        converter.setJwtGrantedAuthoritiesConverter(roleConverter);
        return converter;
    }

    @Bean
    public KeycloakRealmRoleConverterSecurity keycloakRealmRoleConverterSecurity() {
        return new KeycloakRealmRoleConverterSecurity();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return new KeycloakOidcAuthoritiesMapperSecurity();
    }
}