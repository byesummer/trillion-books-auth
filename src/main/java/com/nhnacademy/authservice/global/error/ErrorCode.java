package com.nhnacademy.authservice.global.error;

import lombok.Getter;
import org.springframework.http.HttpStatus;

@Getter
public enum ErrorCode {
    TOKEN_EXPIRED(HttpStatus.UNAUTHORIZED, "토큰이 만료되었습니다."),
    TOKEN_INVALID(HttpStatus.UNAUTHORIZED, "유효하지 않은 토큰입니다."),
    TOKEN_BLACKLISTED(HttpStatus.UNAUTHORIZED, "로그아웃된 토큰입니다."),
    REFRESH_TOKEN_REUSED(HttpStatus.UNAUTHORIZED, "재사용이 감지되어 세션이 무효화되었습니다."),
    REFRESH_TOKEN_NOT_FOUND(HttpStatus.UNAUTHORIZED, "리프레시 토큰 세션을 찾을 수 없습니다."),
    MEMBER_NOT_FOUND(HttpStatus.NOT_FOUND, "회원을 찾을 수 없습니다."),
    USER_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 존재하는 사용자입니다."),
    OAUTH_EMAIL_NOT_FOUND(HttpStatus.UNAUTHORIZED, "소셜 계정에서 이메일을 가져오지 못했습니다."),
    LOCK_ACQUISITION_FAILED(HttpStatus.SERVICE_UNAVAILABLE, "요청이 몰려 처리하지 못했습니다. 잠시 후 다시 시도해주세요."),

    // 프레임워크(Spring Security 등)가 던지는 예외용 — AuthException 계층엔 안 묶이지만
    // 응답 형식(title/status)은 동일한 ErrorCode로 통일한다.
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "입력값이 유효하지 않습니다."),
    OAUTH_AUTHENTICATION_REQUIRED(HttpStatus.UNAUTHORIZED, "소셜 로그인 인증에 실패했습니다."),
    ACCESS_DENIED(HttpStatus.FORBIDDEN, "접근 권한이 없습니다."),
    INTERNAL_SERVER_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "서버 내부 오류가 발생했습니다.");

    private final HttpStatus status;
    private final String defaultMessage;

    ErrorCode(HttpStatus status, String defaultMessage) {
        this.status = status;
        this.defaultMessage = defaultMessage;
    }
}
