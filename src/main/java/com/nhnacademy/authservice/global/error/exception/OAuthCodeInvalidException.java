package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class OAuthCodeInvalidException extends AuthException {
    public OAuthCodeInvalidException() {
        super(ErrorCode.OAUTH_CODE_INVALID);
    }
}
