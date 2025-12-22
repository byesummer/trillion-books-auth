package com.nhnacademy.authservice.auth.controller;

import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.service.AuthService;
import com.nhnacademy.authservice.global.error.ErrorResponse;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/validate")
    public ResponseEntity<Void> validateToken(@RequestHeader(HttpHeaders.AUTHORIZATION) String authorizationHeader) {
        try {
            // AuthService에서 검증 수행 및 정보 추출
            Map<String, String> memberInfo = authService.validateToken(authorizationHeader);

            return ResponseEntity.ok()
                    .header("X-Member-Id", memberInfo.get("memberId"))
                    .header("X-Member-Role", memberInfo.get("role"))
                    .build();
        } catch (Exception e) {
            log.warn("Token validation failed: {}", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest request) {
        try {
            TokenResponse tokenResponse = authService.login(request);
            // Body에 토큰 반환 (FeignClient가 받기 편하도록)
            return ResponseEntity.ok(tokenResponse);
        } catch (Exception ex) {
            return handleLoginException(ex);
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader(HttpHeaders.AUTHORIZATION) String accessToken) {
        authService.logout(accessToken);
        return ResponseEntity.ok().build();
    }

    @PostMapping("/reissue")
    public ResponseEntity<TokenResponse> reissue(@RequestHeader("X-Refresh-Token") String refreshToken) {
        return ResponseEntity.ok(authService.reissue(refreshToken));
    }

    // 회원 탈퇴
    @DeleteMapping("/withdraw")
    public ResponseEntity<Void> withdraw(
            @RequestHeader("X-Member-Id") Long memberId,
            @RequestHeader(value = "Refresh-Token", required = false) String refreshToken
    ) {
        authService.withdrawMember(refreshToken);
        log.info("회원 탈퇴 완료: MemberEmail {}", memberId);
        return ResponseEntity.ok().build();
    }

    private ResponseEntity<?> handleLoginException(Exception ex) {
        Throwable cause = ex;
        if (ex instanceof org.springframework.security.authentication.InternalAuthenticationServiceException) {
            cause = ex.getCause();
        }

        if (cause instanceof MemberStateConflictException e) {
            HttpStatus status = HttpStatus.FORBIDDEN;
            String errorCode = (e.getState() == MemberState.DORMANT) ? "DORMANT_ACCOUNT" : "WITHDRAWAL_ACCOUNT";
            return ResponseEntity.status(status)
                    .body(ErrorResponse.of(errorCode, status.value(), e.getMessage()));
        }
        if (ex instanceof BadCredentialsException) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(ErrorResponse.of("BAD_CREDENTIALS", 401, "아이디 또는 비밀번호가 일치하지 않습니다."));
        }
        log.error("Login Error", ex);
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(ErrorResponse.of("INTERNAL_ERROR", 500, "로그인 중 서버 오류가 발생했습니다."));
    }
}