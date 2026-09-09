package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtBuilder;
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

    public String getJti(String token){
        return getClaims(token).getId();
    }

    private TokenKinds getCategory(String token) {
        return TokenKinds.valueOf(getClaims(token).get("category", String.class));
    }

    // 토큰 만료 확인
    private Boolean isExpired(String token) {
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
        if (isExpired(token)) {
            throw new IllegalArgumentException("Expired token");
        }
        if (TokenKinds.ACCESS_TOKEN!= getCategory(token)) {
            throw new InvalidRefreshTokenException("Invalid token category");
        }
    }
    public void validateRefreshToken(String token) {
        if (token == null) {
            throw new InvalidRefreshTokenException("Refresh token is null");
        }
        if(isExpired(token)) {
            throw new InvalidRefreshTokenException("Refresh token expired");
        }

        if (TokenKinds.REFRESH_TOKEN!= getCategory(token)) {
            throw new InvalidRefreshTokenException("Invalid token category");
        }
    }
}