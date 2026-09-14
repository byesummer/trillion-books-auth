package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class TokenBlacklistedException extends AuthException {
    public TokenBlacklistedException() {
        super(ErrorCode.TOKEN_BLACKLISTED);
    }
}
