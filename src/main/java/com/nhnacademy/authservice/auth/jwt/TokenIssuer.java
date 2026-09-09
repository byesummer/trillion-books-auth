package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.auth.dto.TokenResponse;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.UUID;

@Component
@RequiredArgsConstructor
public class TokenIssuer {
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public TokenResponse issue(Long memberId, String role) {
        String jti = UUID.randomUUID().toString();
        String accessToken  = jwtUtil.createJwt(memberId, TokenKinds.ACCESS_TOKEN, role);
        String refreshToken = jwtUtil.createJwt(memberId, TokenKinds.REFRESH_TOKEN, role, jti);
        refreshTokenRepository.save(new RefreshToken(memberId, jti, role));
        return new TokenResponse(accessToken, refreshToken);
    }
}
