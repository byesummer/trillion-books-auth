package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;

public class LockAcquisitionException extends AuthException {
    public LockAcquisitionException(String message) {
        super(ErrorCode.LOCK_ACQUISITION_FAILED, message);
    }
}
