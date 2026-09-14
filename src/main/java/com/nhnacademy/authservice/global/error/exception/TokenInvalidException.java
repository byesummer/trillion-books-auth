package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class TokenInvalidException extends AuthException {
    public TokenInvalidException() {
        super(ErrorCode.TOKEN_INVALID);
    }
}
