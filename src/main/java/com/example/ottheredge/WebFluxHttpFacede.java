package com.example.ottheredge;

import io.netty.handler.codec.http.HttpHeaderNames;
import org.keycloak.adapters.authorization.TokenPrincipal;
import org.keycloak.adapters.authorization.spi.HttpRequest;
import org.keycloak.adapters.authorization.spi.HttpResponse;
import org.springframework.cloud.gateway.support.ServerWebExchangeUtils;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.core.io.buffer.DataBufferUtils;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.web.reactive.function.BodyExtractors;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.netty.http.server.HttpServerResponse;

import java.io.*;
import java.util.List;
import java.util.Objects;

public class WebFluxHttpFacede implements HttpRequest, HttpResponse {


    private final ServerWebExchange exchange;
    private final long readTimeout;
    private final HttpRequest request;
    private final HttpResponse response;
    private final TokenPrincipal tokenPrincipal;

    public WebFluxHttpFacede(ServerWebExchange exchange, String token, long readTimeout) {
        this.exchange = exchange;
        this.readTimeout = readTimeout;

        this.request = createRequest(exchange);
        this.response = createResponse(exchange);

        tokenPrincipal = new TokenPrincipal() {
            @Override
            public String getRawToken() {
                return token;
            }
        };
    }

    public WebFluxHttpFacede(ServerWebExchange exchange) {
        this.exchange = exchange;
        this.readTimeout = 30;

        this.request = createRequest(exchange);
        this.response = createResponse(exchange);

        tokenPrincipal = extractBearerToken(exchange);
    }

    protected TokenPrincipal extractBearerToken(ServerWebExchange exchange) {

        ServerHttpRequest request =exchange.getRequest();
        List<String> authorizationHeaderValues = request.getHeaders().getOrEmpty("Authorization");
        authorizationHeaderValues.addAll(request.getHeaders().getOrEmpty("authorization"));

        return authorizationHeaderValues.stream()
                .filter(header-> header.startsWith("Bearer"))
                .findFirst()
                .map(value -> {
                    String[] parts = value.trim().split("\\s+");

                    if (parts.length != 2) {
                        return "";
                    }

                    String bearer = parts[0];

                    if (bearer.equalsIgnoreCase("Bearer")) {
                        return parts[1];
                    }
                    return null;
                })
                .map( token -> {
                    return new TokenPrincipal() {
                        @Override
                        public String getRawToken() {
                            return token;
                        }
                    };
                })
                .orElseThrow(() -> new InvalidBearerTokenException("Bearer not found"))
                ;

    }

    private HttpResponse createResponse(ServerWebExchange exchange) {
        ServerHttpResponse response = exchange.getResponse();

        return new HttpResponse() {

            @Override
            public void setHeader(String name, String value) {
                response.getHeaders().set(name, value);
            }

            @Override
            public void sendError(int code) {
                response.setStatusCode(HttpStatusCode.valueOf(code));
            }

            @Override
            public void sendError(int code, String message) {
                response.getHeaders().setContentType(MediaType.TEXT_HTML);
                response.setStatusCode(HttpStatusCode.valueOf(code));
                //response.setStatusMessage(message);
            }
        };
    }

    private HttpRequest createRequest(ServerWebExchange exchange) {
        ServerHttpRequest req = exchange.getRequest();
        return new HttpRequest() {
            @Override
            public String getRelativePath() {
                return req.getPath().value();
            }

            @Override
            public String getMethod() {
                return req.getMethod().name();
            }

            @Override
            public String getURI() {
                return req.getURI().toString();
            }

            @Override
            public List<String> getHeaders(String name) {
                return req.getHeaders().get(name);
            }

            @Override
            public String getFirstParam(String name) {
                return req.getQueryParams().getFirst(name);
            }

            @Override
            public String getCookieValue(String name) {
                return request.getCookieValue(name);
            }

            @Override
            public String getRemoteAddr() {
                return Objects.requireNonNull(req.getRemoteAddress()).getHostString();
            }

            @Override
            public boolean isSecure() {
                return req.getSslInfo() != null;
            }

            @Override
            public String getHeader(String name) {
                return req.getHeaders().getFirst(name);
            }

            @Override
            public InputStream getInputStream(boolean buffered) {


                PipedOutputStream osPipe = new PipedOutputStream();
                PipedInputStream isPipe;
                try {
                    isPipe = new PipedInputStream(osPipe);


                    DataBufferUtils.write(exchange.getRequest().getBody(), osPipe)
                            .subscribe(DataBufferUtils.releaseConsumer());

                    return isPipe;
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }

            @Override
            public TokenPrincipal getPrincipal() {
                return tokenPrincipal;
            }
        };
    }

    @Override
    public String getRelativePath() {
        return request.getRelativePath();
    }

    @Override
    public String getMethod() {
        return request.getMethod();
    }

    @Override
    public String getURI() {
        return request.getURI();
    }

    @Override
    public List<String> getHeaders(String name) {
        return request.getHeaders(name);
    }

    @Override
    public String getFirstParam(String name) {
        return request.getFirstParam(name);
    }

    @Override
    public String getCookieValue(String name) {
        return request.getCookieValue(name);
    }

    @Override
    public String getRemoteAddr() {
        return request.getRemoteAddr();
    }

    @Override
    public boolean isSecure() {
        return request.isSecure();
    }

    @Override
    public String getHeader(String name) {
        return request.getHeader(name);
    }

    @Override
    public InputStream getInputStream(boolean buffered) {
        return request.getInputStream(buffered);
    }

    @Override
    public TokenPrincipal getPrincipal() {
        return request.getPrincipal();
    }

    @Override
    public void sendError(int statusCode) {
        response.sendError(statusCode);
    }

    @Override
    public void sendError(int statusCode, String reason) {
        response.sendError(statusCode, reason);
    }

    @Override
    public void setHeader(String name, String value) {
        response.setHeader(name, value);
    }
}
