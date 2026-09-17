package com.nhnacademy.authservice.auth.service;


import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.global.error.exception.OAuthCodeInvalidException;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class OAuth2CodeService {
    private static final String KEY_PREFIX = "oauth2code:";
    private static final Duration TTL = Duration.ofSeconds(60);

    private final StringRedisTemplate redisTemplate;
    private final TokenIssuer tokenIssuer;

    public String issueCode(Long memberId, String role){
        String code = UUID.randomUUID().toString();
        redisTemplate.opsForValue().set(KEY_PREFIX + code, memberId + ":" + role, TTL);
        return code;
    }

    public TokenResponse exchange(String code){
        String key = KEY_PREFIX + code;
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) {
            throw new OAuthCodeInvalidException();
        }
        redisTemplate.delete(key); // 1회용 — 조회 즉시 폐기
        String[] parts = value.split(":", 2);
        return tokenIssuer.issue(Long.valueOf(parts[0]), parts[1]);
    }
}
