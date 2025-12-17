package com.nhnacademy.authservice.auth.dto;

public record TokenResponse(
        String accessToken,
        String refreshToken
) {}
