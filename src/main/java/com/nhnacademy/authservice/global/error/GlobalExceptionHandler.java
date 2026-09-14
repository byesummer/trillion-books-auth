package com.nhnacademy.authservice.global.error;

import com.nhnacademy.authservice.global.error.exception.AuthException;
import com.nhnacademy.authservice.global.error.exception.LockAcquisitionException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

@Slf4j
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuthException(AuthException e) {
        ErrorCode code = e.getErrorCode();
        log.warn("[{}] {}", code.name(), e.getMessage());
        ErrorResponse response = ErrorResponse.of(code.name(), code.getStatus().value(), e.getMessage());
        return ResponseEntity.status(code.getStatus())
                .header("X-Auth-Error", code.name().toLowerCase())
                .body(response);
    }

    // 락 획득 실패만 Retry-After 헤더가 추가로 필요해 다른 핸들러로 처리
    @ExceptionHandler(LockAcquisitionException.class)
    public ResponseEntity<ErrorResponse> handleLockAcquisition(LockAcquisitionException e) {
        ErrorCode code = e.getErrorCode();
        log.warn("[{}] {}", code.name(), e.getMessage());
        ErrorResponse response = ErrorResponse.of(code.name(), code.getStatus().value(), e.getMessage());
        return ResponseEntity.status(code.getStatus())
                .header("X-Auth-Error", code.name().toLowerCase())
                .header("Retry-After", "1")
                .body(response);
    }


    // 400 Bad Request Error (@Valid 유효성 검사 실패 시)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException e) {
        ErrorCode code = ErrorCode.VALIDATION_FAILED;
        log.info("[{}] {}", code.name(), e.getBindingResult());
        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse response = ErrorResponse.of(
                code.name(),
                code.getStatus().value(),
                code.getDefaultMessage(),
                errors
        );
        return new ResponseEntity<>(response, code.getStatus());
    }

    // 401 Unauthorized Error (OAuth2 로그인 인증 필수 정보 누락)
    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2AuthenticationException(OAuth2AuthenticationException e) {
        ErrorCode code = ErrorCode.OAUTH_AUTHENTICATION_REQUIRED;
        log.warn("[{}] {}", code.name(), e.getMessage());
        ErrorResponse response = ErrorResponse.of(code.name(), code.getStatus().value(), e.getMessage());
        return new ResponseEntity<>(response, code.getStatus());
    }

    // 403 Forbidden Error (접근 권한이 없는 경우 — 현재 코드베이스엔 permitAll뿐이라 실제 발생 경로 없음.
    // method security를 나중에 켰을 때를 대비한 방어적 핸들러로 유지)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException e) {
        ErrorCode code = ErrorCode.ACCESS_DENIED;
        log.warn("[{}] {}", code.name(), e.getMessage());
        ErrorResponse response = ErrorResponse.of(code.name(), code.getStatus().value(), e.getMessage());
        return new ResponseEntity<>(response, code.getStatus());
    }

    // 500 Internal Server Error
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception e) {
        ErrorCode code = ErrorCode.INTERNAL_SERVER_ERROR;
        log.error("[{}]", code.name(), e);
        ErrorResponse response = ErrorResponse.of(
                code.name(),
                code.getStatus().value(),
                code.getDefaultMessage() + ": " + e.getMessage()
        );
        return new ResponseEntity<>(response, code.getStatus());
    }
}
