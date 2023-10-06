package com.example.ottheredge;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.keycloak.AuthorizationContext;
import org.keycloak.adapters.authorization.PolicyEnforcer;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.keycloak.adapters.authorization.integration.elytron.ServletHttpRequest;
import org.keycloak.adapters.authorization.integration.elytron.ServletHttpResponse;
import org.keycloak.adapters.authorization.spi.ConfigurationResolver;
import org.keycloak.adapters.authorization.spi.HttpRequest;
import org.keycloak.representations.adapters.config.PolicyEnforcerConfig;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.function.Function;

public class ReactiveWebServerPolicyEnforcerFilter implements WebFilter {


    private static final Log logger = LogFactory.getLog(ReactiveWebServerPolicyEnforcerFilter.class);
    private ReactiveConfigurationResolver reactiveConfigurationResolver;

    private final Map<PolicyEnforcerConfig, PolicyEnforcer> policyEnforcerTenantMap;
//    private ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager;

    public ReactiveWebServerPolicyEnforcerFilter() { //ReactiveAuthorizationManager<? super ServerWebExchange> authorizationManager) {
//        this.authorizationManager = authorizationManager;
        policyEnforcerTenantMap = Collections.synchronizedMap(new HashMap<>());
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {


        return ReactiveSecurityContextHolder.getContext()
                .filter((c) -> c.getAuthentication() != null)
                .map(SecurityContext::getAuthentication)
                .as((authentication) -> {
                    PolicyEnforcer policyEnforcer = getOrCreatePolicyEnforcer(exchange);
                    WebFluxHttpFacede httpFacade = new WebFluxHttpFacede(exchange);
                    AuthorizationContext result = policyEnforcer.enforce(httpFacade, httpFacade);
                  if(!result.isGranted()){
                      return Mono.error(new AccessDeniedException("Access Denied"));
                  }
                  return Mono.empty();

                })
                .then()
                .doOnSuccess((it) -> logger.debug("Authorization successful"))
                .doOnError(AccessDeniedException.class,
                        (ex) -> logger.debug(LogMessage.format("Authorization failed: %s", ex.getMessage())))
                .switchIfEmpty(chain.filter(exchange));
    }


    private PolicyEnforcer getOrCreatePolicyEnforcer(ServerWebExchange exchange) {
//        return policyEnforcerTenantMap.computeIfAbsent(configResolver.resolve(request),
//                new Function<PolicyEnforcerConfig, PolicyEnforcer>() {
//            @Override
//            public PolicyEnforcer apply(PolicyEnforcerConfig enforcerConfig) {
//                return createPolicyEnforcer(exchange, enforcerConfig);
//            }
//        });
        PolicyEnforcerConfig enforcerConfig = new PolicyEnforcerConfig();


        enforcerConfig.setAuthServerUrl("http://localhost:8080/auth");
        enforcerConfig.setResource("gw-edge-service-client");
        enforcerConfig.setRealm("beans");
        enforcerConfig.setCredentials(Map.of("secret", "77nT9BRBlzJWd0GpwACyzQVrmmFdHNIv"));

        return createPolicyEnforcer(exchange, enforcerConfig);
    }


    private Mono<Void> handleAuthenticationFailure(ServerHttpResponse response, Exception ex) {
        this.logger.debug("Failed to process OIDC Back-Channel Logout", ex);
        response.setRawStatusCode(HttpStatus.UNAUTHORIZED.value());
        OAuth2Error error = oauth2Error(ex);
        byte[] bytes = String.format("""
                {
                	"error_code": "%s",
                	"error_description": "%s",
                	"error_uri: "%s"
                }
                """, error.getErrorCode(), error.getDescription(), error.getUri()).getBytes(StandardCharsets.UTF_8);
        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Flux.just(buffer));
    }

    private OAuth2Error oauth2Error(Exception ex) {
        if (ex instanceof OAuth2AuthenticationException oauth2) {
            return oauth2.getError();
        }
        return new OAuth2Error(OAuth2ErrorCodes.UNAUTHORIZED_CLIENT, ex.getMessage(),
                "https://openid.net/specs/openid-connect-backchannel-1_0.html#Validation");
    }

    protected PolicyEnforcer createPolicyEnforcer(ServerWebExchange exchange, PolicyEnforcerConfig enforcerConfig) {
        String authServerUrl = enforcerConfig.getAuthServerUrl();

        return PolicyEnforcer.builder()
                .authServerUrl(authServerUrl)
                .realm(enforcerConfig.getRealm())
                .clientId(enforcerConfig.getResource())
                .credentials(enforcerConfig.getCredentials())
                .bearerOnly(false)
                .enforcerConfig(enforcerConfig).build();
    }
}