package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class MemberNotFoundException extends AuthException {
    public MemberNotFoundException(String message) {
        super(ErrorCode.MEMBER_NOT_FOUND, message);
    }
}
