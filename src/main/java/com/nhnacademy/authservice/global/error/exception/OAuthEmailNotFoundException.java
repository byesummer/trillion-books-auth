package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class OAuthEmailNotFoundException extends AuthException {
    public OAuthEmailNotFoundException(String message) {
        super(ErrorCode.OAUTH_EMAIL_NOT_FOUND, message);
    }
}
