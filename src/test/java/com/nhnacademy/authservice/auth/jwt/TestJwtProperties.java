package com.nhnacademy.authservice.auth.jwt;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties("jwt")
public record TestJwtProperties(String secret,String timeOutAccessToken,String timeOutRefreshToken,String rightAccessToken,String rightRefreshToken) {
}
