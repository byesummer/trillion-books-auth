package com.nhnacademy.authservice.auth.service;

import org.jspecify.annotations.NonNull;
import org.springframework.stereotype.Component;

@Component
public class TokenParser {
    String getToken(@NonNull String authHeader) {
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Authorization header");
        }
        return authHeader.substring(7);
    }
}
