package com.nhnacademy.authservice.global.error.exception;

public class OAuthEmailNotFoundException extends RuntimeException {
    public OAuthEmailNotFoundException(String message) {
        super(message);
    }
}
