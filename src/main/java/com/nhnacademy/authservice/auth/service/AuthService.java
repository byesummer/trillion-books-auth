package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.CustomUserDetails;
import com.nhnacademy.authservice.auth.dto.LoginRequest;
import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.jwt.JWTUtil;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import com.nhnacademy.authservice.global.error.exception.InvalidRefreshTokenException;
import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import io.jsonwebtoken.ExpiredJwtException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@Transactional
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final MemberRepository memberRepository;
    private final StringRedisTemplate redisTemplate;

    public Map<String, String> validateToken(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new IllegalArgumentException("Invalid Authorization header");
        }
        String token = authHeader.substring(7);

        // 블랙리스트 확인
        if (Boolean.TRUE.equals(redisTemplate.hasKey("BL:" + token))) {
            throw new IllegalArgumentException("Blacklisted token");
        }

        // JWTUtil 내부에서 ExpiredJwtException 발생 시 Controller가 잡음
        if (jwtUtil.isExpired(token)) {
            throw new IllegalArgumentException("Expired token");
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

        CustomUserDetails userDetails = (CustomUserDetails) authentication.getPrincipal();

        Member member = memberRepository.findById(userDetails.getMemberId())
                .orElseThrow(() -> new UsernameNotFoundException("Member not found"));

        if (member.getMemberState() == MemberState.DORMANT) {
            throw new MemberStateConflictException("휴면 계정입니다.", MemberState.DORMANT);
        }

        member.setMemberLatestLoginAt(LocalDate.now());

        String role = authentication.getAuthorities().iterator().next().getAuthority();
        if(role.startsWith("ROLE_")) role = role.substring(5);

        return generateTokens(userDetails.getMemberId(), role);
    }

    public TokenResponse reissue(String refreshToken) {
        if (refreshToken == null) {
            throw new InvalidRefreshTokenException("Refresh token is null");
        }

        try {
            // 리프레시 토큰 만료 체크
            if(jwtUtil.isExpired(refreshToken)) {
                throw new InvalidRefreshTokenException("Refresh token expired");
            }
        } catch (ExpiredJwtException e) {
            throw new InvalidRefreshTokenException("Refresh token expired");
        }

        String category = jwtUtil.getCategory(refreshToken);
        if (!"refresh".equals(category)) {
            throw new InvalidRefreshTokenException("Invalid token category");
        }

        RefreshToken storedToken = refreshTokenRepository.findById(refreshToken)
                .orElseThrow(() -> new InvalidRefreshTokenException("Invalid refresh token (Not found in Redis)"));

        Long memberId = storedToken.getMemberId();
        String role = storedToken.getRole();

        refreshTokenRepository.deleteById(refreshToken);
        return generateTokens(memberId, role);
    }

    public void logout(String accessToken) {
        if (accessToken != null && accessToken.startsWith("Bearer ")) {
            String token = accessToken.substring(7);

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
    }

    // 로그아웃 처리 (Refresh Token 삭제)
    public void withdrawMember(String refreshToken) {
        if (refreshToken != null && refreshTokenRepository.existsById(refreshToken)) {
            refreshTokenRepository.deleteById(refreshToken);
        }
    }

    private TokenResponse generateTokens(Long memberId, String role) {
        long accessExpire = 1800000L;      // 30분
        long refreshExpire = 86400000L;   // 24시간

        String accessToken = jwtUtil.createJwt(memberId, "access", role, accessExpire);
        String refreshToken = jwtUtil.createJwt(memberId, "refresh", role, refreshExpire);

        refreshTokenRepository.save(new RefreshToken(refreshToken, memberId, role));

        return new TokenResponse(accessToken, refreshToken);
    }
}