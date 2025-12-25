package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

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

    public String createJwt(Long memberId, TokenKinds category, String role) {
        Date now = new Date();
        Date past = new Date(now.getTime() - 60000);
        Date validity = new Date(now.getTime() + category.getExpiredTime());

        return Jwts.builder()
                .subject(memberId.toString())
                .claim("category",category)
                .claim("role", role)
                .issuedAt(past)
                .expiration(validity)
                .signWith(secretKey)
                .compact();
    }
    //3개이상 다형성 풀어보셈. 제안
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