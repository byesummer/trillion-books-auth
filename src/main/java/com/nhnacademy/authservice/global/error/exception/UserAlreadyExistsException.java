package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class UserAlreadyExistsException extends AuthException {
    public UserAlreadyExistsException(String message) {
        super(ErrorCode.USER_ALREADY_EXISTS, message);
    }
}
