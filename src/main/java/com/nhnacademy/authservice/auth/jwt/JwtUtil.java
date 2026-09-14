package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.global.error.exception.TokenExpiredException;
import com.nhnacademy.authservice.global.error.exception.TokenInvalidException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey secretKey;

    public JwtUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims getClaims(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(secretKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
        } catch (ExpiredJwtException e) {
            throw new TokenExpiredException(e.getClaims());
        } catch (JwtException | IllegalArgumentException e) {
            throw new TokenInvalidException();
        }
    }

    public Long getMemberId(String token) {
        return Long.valueOf(getClaims(token).getSubject());
    }

    public String getRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    public String getJti(String token){
        return getClaims(token).getId();
    }

    private TokenKinds getCategory(String token) {
        try {
            return TokenKinds.valueOf(getClaims(token).get("category", String.class));
        } catch (IllegalArgumentException e) {
            throw new TokenInvalidException();
        }
    }

    // 엑세스 토큰 만료 시간 계산. (Black List)
    public Long getExpiration(String token) {
        return getClaims(token).getExpiration().getTime();
    }

    public String createJwt(Long memberId, TokenKinds category, String role){
        return createJwt(memberId, category, role, null);
    }

    public String createJwt(Long memberId, TokenKinds category, String role, String jti) {
        Date now = new Date();
        Date past = new Date(now.getTime() - 60000);
        Date validity = new Date(now.getTime() + category.getExpiredTime());

        JwtBuilder jwt = Jwts.builder()
                .subject(memberId.toString())
                .claim("category",category)
                .claim("role", role)
                .issuedAt(past)
                .expiration(validity);
        if(jti != null){
            jwt.id(jti);
        }

        return jwt.signWith(secretKey).compact();
    }

    public void validateAccessToken(String token) {
        // 만료·서명 오류는 getClaims(→getCategory)가 이미 TokenExpiredException/TokenInvalidException으로 던짐
        if (TokenKinds.ACCESS_TOKEN != getCategory(token)) {
            throw new TokenInvalidException();
        }
    }

    public void validateRefreshToken(String token) {
        if (token == null) {
            throw new TokenInvalidException();
        }
        if (TokenKinds.REFRESH_TOKEN != getCategory(token)) {
            throw new TokenInvalidException();
        }
    }
}
