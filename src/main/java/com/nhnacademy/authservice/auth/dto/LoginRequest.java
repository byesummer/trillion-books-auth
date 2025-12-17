package com.nhnacademy.authservice.auth.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record LoginRequest(
        @NotBlank @Email
        String memberEmail,
        @NotBlank
        String memberPassword
) {}