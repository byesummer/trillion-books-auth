package com.nhnacademy.authservice.global.error;

import java.util.Map;

public record ErrorResponse(
        String title,
        int status,
        String message,
        Map<String, String> validationErrors
) {
    public static ErrorResponse of(String title, int status, String message) {
        return new ErrorResponse(title, status, message, null);
    }

    public static ErrorResponse of(String title, int status, String message, Map<String, String> validationErrors) {
        return new ErrorResponse(title, status, message, validationErrors);
    }
}