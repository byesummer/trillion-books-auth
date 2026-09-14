package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class RefreshTokenReusedException extends AuthException {
    public RefreshTokenReusedException() {
        super(ErrorCode.REFRESH_TOKEN_REUSED);
    }
}
