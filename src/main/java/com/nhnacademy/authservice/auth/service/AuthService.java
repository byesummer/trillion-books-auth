package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.CustomUserDetails;
import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.jwt.JwtUtil;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.global.error.exception.LockAcquisitionException;
import com.nhnacademy.authservice.global.error.exception.RefreshTokenNotFoundException;
import com.nhnacademy.authservice.global.error.exception.RefreshTokenReusedException;
import com.nhnacademy.authservice.global.error.exception.TokenBlacklistedException;
import com.nhnacademy.authservice.global.error.exception.TokenExpiredException;
import com.nhnacademy.authservice.member.entity.Member;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.redisson.api.RLock;
import org.redisson.api.RedissonClient;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final StringRedisTemplate redisTemplate;
    private final TokenParser tokenParser;
    private final TokenIssuer tokenIssuer;
    private final RedissonClient redissonClient;

    public Map<String, String> validateToken(String authHeader) {
        String token = tokenParser.getToken(authHeader);
        jwtUtil.validateAccessToken(token);

        if (Boolean.TRUE.equals(redisTemplate.hasKey("BL:" + token))) {
            throw new TokenBlacklistedException();
        }
        Long memberId = jwtUtil.getMemberId(token);
        String role = jwtUtil.getRole(token);

        Map<String, String> result = new HashMap<>();
        result.put("memberId", String.valueOf(memberId));
        result.put("role", role);
        return result;
    }

    public TokenResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.memberEmail(), request.memberPassword()));

        Member member = ((CustomUserDetails) authentication.getPrincipal()).getMember();
        member.setMemberLatestLoginAt(LocalDate.now());

        return tokenIssuer.issue(member.getMemberId(), member.getMemberRole().name());
    }

    public TokenResponse reissue(String refreshToken) {
        jwtUtil.validateRefreshToken(refreshToken);

        Long memberId = jwtUtil.getMemberId(refreshToken);

        RLock lock = redissonClient.getLock("reissue:lock:" + memberId);
        boolean acquired;
        try {
            acquired = lock.tryLock(3, 5, TimeUnit.SECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LockAcquisitionException("Lock acquisition interrupted");
        }
        if (!acquired) {
            throw new LockAcquisitionException("Could not acquire reissue lock");
        }

        try {
            RefreshToken storedToken = refreshTokenRepository.findById(memberId)
                    .orElseThrow(RefreshTokenNotFoundException::new);

            String presentedJti = jwtUtil.getJti(refreshToken);
            if (!storedToken.getJti().equals(presentedJti)) {
                refreshTokenRepository.deleteById(memberId);
                log.warn("Refresh token reuse detected. memberId={}, session invalidated", memberId);
                throw new RefreshTokenReusedException();
            }

            return tokenIssuer.issue(memberId, storedToken.getRole());
        } finally {
            if (lock.isHeldByCurrentThread()) {
                lock.unlock();
            }
        }
    }

    public void logout(String authHeader) {
        String token = tokenParser.getToken(authHeader);
        Long memberId;
        try {
            memberId = jwtUtil.getMemberId(token);
        } catch (TokenExpiredException e) {
            // 서명은 유효했지만 이미 만료된 토큰 — 블랙리스트에 올릴 필요는 없고(어차피 무효),
            // claims에서 memberId만 꺼내 RT 세션은 정리한다.
            memberId = Long.valueOf(e.getClaims().getSubject());
            log.warn("Logout with expired access token (blacklist skipped, session still cleared): memberId={}", memberId);
            refreshTokenRepository.deleteById(memberId);
            return;
        }

        long remainTime = jwtUtil.getExpiration(token) - System.currentTimeMillis();
        if (remainTime > 0) {
            redisTemplate.opsForValue().set("BL:" + token, "logout", remainTime, TimeUnit.MILLISECONDS);
        }
        refreshTokenRepository.deleteById(memberId);
    }

    public void withdrawMember(String authHeader) {
        String token = tokenParser.getToken(authHeader);
        refreshTokenRepository.deleteById(jwtUtil.getMemberId(token));
    }
}
