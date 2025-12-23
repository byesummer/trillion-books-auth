package com.nhnacademy.authservice.auth.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component
public class JWTUtil {

    private final SecretKey secretKey;

    public JWTUtil(@Value("${spring.jwt.secret}") String secret) {
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }

    private Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    public Long getMemberId(String token) {
        return Long.valueOf(getClaims(token).getSubject());
    }

    public String getRole(String token) {
        return getClaims(token).get("role", String.class);
    }

    public String getCategory(String token) {
        return getClaims(token).get("category", String.class);
    }

    // 토큰 만료 확인
    public Boolean isExpired(String token) {
        try {
            getClaims(token);
            return false;
        } catch (ExpiredJwtException e) {
            return true;
        }
    }

    // 엑세스 토큰 만료 시간 계산. (Black List)
    public Long getExpiration(String token) {
        return getClaims(token).getExpiration().getTime();
    }

    public String createJwt(Long memberId, String category, String role, Long expiredMs) {
        Date now = new Date();
        Date past = new Date(now.getTime() - 60000);
        Date validity = new Date(now.getTime() + expiredMs);

        return Jwts.builder()
                .subject(memberId.toString())
                .claim("category",category)
                .claim("role", role)
                .issuedAt(past)
                .expiration(validity)
                .signWith(secretKey)
                .compact();
    }
}