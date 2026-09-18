package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class OAuth2RequestSerializationException extends AuthException {
    public OAuth2RequestSerializationException() {
        super(ErrorCode.OAUTH_REQUEST_SERIALIZATION_FAILED);
    }
}
