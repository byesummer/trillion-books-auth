package com.nhnacademy.authservice.global.error;

import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import com.nhnacademy.authservice.global.error.exception.MemberNotFoundException;
import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import com.nhnacademy.authservice.global.error.exception.UserAlreadyExistsException;
import com.nhnacademy.authservice.global.error.exception.*;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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

    // 409 Conflict Error (회원가입 시 이미 존재하는 이메일일 경우)
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<ErrorResponse> handleUserAlreadyExistsException(UserAlreadyExistsException e) {
        log.warn("회원가입 실패 - 이미 존재하는 사용자: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "User Already Exists",
                HttpStatus.CONFLICT.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.CONFLICT);
    }

    // 404 Not Found Error (Spring Security 관련 사용자를 찾을 수 없는 경우)
    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFoundException(UsernameNotFoundException e) {
        log.warn("사용자를 찾을 수 없음(Security): {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "User Not Found",
                HttpStatus.NOT_FOUND.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    // 404 Not Found Error (비즈니스 로직 상 회원을 찾을 수 없는 경우)
    @ExceptionHandler(MemberNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleMemberNotFoundException(MemberNotFoundException e) {
        log.warn("회원을 찾을 수 없음: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "Member Not Found",
                HttpStatus.NOT_FOUND.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.NOT_FOUND);
    }

    // 400 Bad Request Error (@Valid 유효성 검사 실패 시)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleValidationExceptions(MethodArgumentNotValidException e) {
        log.info("유효성 검사 실패: {}", e.getBindingResult());
        Map<String, String> errors = new HashMap<>();
        e.getBindingResult().getAllErrors().forEach((error) -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ErrorResponse response = ErrorResponse.of(
                "Validation Failed",
                HttpStatus.BAD_REQUEST.value(),
                "입력값이 유효하지 않습니다.",
                errors
        );
        return new ResponseEntity<>(response, HttpStatus.BAD_REQUEST);
    }

    // 401 Unauthorized Error (리프레시 토큰 유효성 검사 실패 시)
    @ExceptionHandler(InvalidRefreshTokenException.class)
    public ResponseEntity<ErrorResponse> handleInvalidRefreshToken(InvalidRefreshTokenException e) {
        log.warn("리프레시 토큰 유효성 검사 실패: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "Invalid Refresh Token",
                HttpStatus.UNAUTHORIZED.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // 401 Unauthorized Error (OAuth2 로그인 인증 필수 정보 누락)
    @ExceptionHandler(OAuth2AuthenticationException.class)
    public ResponseEntity<ErrorResponse> handleOAuth2AuthenticationException(OAuth2AuthenticationException e) {
        log.warn("OAuth2 인증 에러: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "Authentication Required",
                HttpStatus.UNAUTHORIZED.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.UNAUTHORIZED);
    }

    // 403 Forbidden Error (탈퇴한 회원, 휴면 계정 등 로그인은 성공했으나 접근이 불가능한 경우)
    @ExceptionHandler(MemberStateConflictException.class)
    public ResponseEntity<ErrorResponse> handleMemberStateConflict(MemberStateConflictException e) {
        log.warn("계정 상태 문제로 접근 거부: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "Account Suspended",
                HttpStatus.FORBIDDEN.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // 403 Forbidden Error (접근 권한이 없는 경우)
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleAccessDeniedException(AccessDeniedException e) {
        log.warn("접근 권한 없음: {}", e.getMessage());
        ErrorResponse response = ErrorResponse.of(
                "Access Denied",
                HttpStatus.FORBIDDEN.value(),
                e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.FORBIDDEN);
    }

    // 500 Internal Server Error (그 외 모든 예외)
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception e) {
        log.error("Internal Server Error", e);
        ErrorResponse response = ErrorResponse.of(
                "Internal Server Error",
                HttpStatus.INTERNAL_SERVER_ERROR.value(),
                "서버 내부 오류가 발생했습니다: " + e.getMessage()
        );
        return new ResponseEntity<>(response, HttpStatus.INTERNAL_SERVER_ERROR);
    }
}