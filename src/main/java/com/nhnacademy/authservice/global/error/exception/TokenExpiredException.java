package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.global.error.ErrorCode;
import io.jsonwebtoken.Claims;
import lombok.Getter;

/**
 * 서명은 유효하지만 만료된 토큰. jwt의 ExpiredJwtException은 만료돼도 claims를 들고 있어,
 * 로그아웃처럼 "만료된 토큰에서도 memberId는 읽어야 하는" 경우를 위해 claims를 함께 보관한다.
 */
@Getter
public class TokenExpiredException extends AuthException {
    private final Claims claims;

    public TokenExpiredException(Claims claims) {
        super(ErrorCode.TOKEN_EXPIRED);
        this.claims = claims;
    }
}
