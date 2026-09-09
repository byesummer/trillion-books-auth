package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.jwt.JwtUtil;
import com.nhnacademy.authservice.auth.jwt.TokenIssuer;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import com.nhnacademy.authservice.member.entity.Member;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public Map<String, String> validateToken(String authHeader) {
        String token = tokenParser.getToken(authHeader);
        jwtUtil.validateAccessToken(token);

        if (Boolean.TRUE.equals(redisTemplate.hasKey("BL:" + token))) {
            throw new IllegalArgumentException("Blacklisted token");
        }
        Long memberId = jwtUtil.getMemberId(token);
        String role = jwtUtil.getRole(token);

        Map<String, String> result = new HashMap<>();
        result.put("memberId", String.valueOf(memberId));
        result.put("role", role);
        return result;
    }

    public TokenResponse login(LoginRequest request) {
        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.memberEmail(), request.memberPassword()));

        Member member = memberRepository.findByMemberEmail(request.memberEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Member not found"));

        member.validateActive();
        member.setMemberLatestLoginAt(LocalDate.now());

        String role = getRole(authentication);
        return generateTokens(member.getMemberId(), role);
    }

    private @NonNull String getRole(Authentication authentication) {
        String role = authentication.getAuthorities().iterator().next().getAuthority();
        if(role.startsWith("ROLE_")) role = role.substring(5);
        return role;
    }

    public TokenResponse reissue(String refreshToken) {
        jwtUtil.validateRefreshToken(refreshToken);

        Long memberId = jwtUtil.getMemberId(refreshToken);
        RefreshToken storedToken = refreshTokenRepository.findById(memberId)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token (Not found in Redis)"));

        String presentedJti = jwtUtil.getJti(refreshToken);
        if (!storedToken.getJti().equals(presentedJti)) {
            refreshTokenRepository.deleteById(memberId);
            log.warn("Refresh token reuse detected. memberId={}, session invalidated", memberId);
            throw new InvalidRefreshTokenException("Refresh token reuse detected");
        }

        return tokenIssuer.issue(memberId, storedToken.getRole());
    }

    public void logout(String accessToken) {
        String token = tokenParser.getToken(accessToken);
         // Access Token 블랙리스트 등록
        try {
                long expiration = jwtUtil.getExpiration(token);
                long now = new Date().getTime();
                long remainTime = expiration - now;
                if (remainTime > 0) {
                    redisTemplate.opsForValue()
                            .set("BL:" + token, "logout", remainTime, TimeUnit.MILLISECONDS);
                }
        } catch (Exception e) {
                log.warn("Logout failed (Invalid token): {}", e.getMessage());
        }
    }

    // 로그아웃 처리 (Refresh Token 삭제)
    public void withdrawMember(String refreshToken) {
        if (refreshToken != null && refreshTokenRepository.existsById(refreshToken)) {
            refreshTokenRepository.deleteById(refreshToken);
        }
    }
    private TokenResponse generateTokens(Long memberId, String role) {
        String accessToken = jwtUtil.createJwt(memberId, TokenKinds.ACCESS_TOKEN, role);
        String refreshToken = jwtUtil.createJwt(memberId, TokenKinds.REFRESH_TOKEN, role);

        refreshTokenRepository.save(new RefreshToken(refreshToken, memberId, role));

        return new TokenResponse(accessToken, refreshToken);
    }
}