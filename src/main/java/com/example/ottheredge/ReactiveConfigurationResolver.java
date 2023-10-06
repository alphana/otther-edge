package com.example.ottheredge;

import org.keycloak.adapters.authorization.spi.HttpRequest;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.web.server.ServerWebExchange;

public interface ReactiveConfigurationResolver {
    PolicyEnforcerConfig resolve(ServerWebExchange exchange);
}
