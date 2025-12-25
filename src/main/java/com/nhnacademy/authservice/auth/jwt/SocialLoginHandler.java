package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

@Component
@RequiredArgsConstructor
public class SocialLoginHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JWTUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    // 프론트 서버 주소 (application.yml에서 주입)
    @Value("${front.server.url:http://localhost:8081}")
    private String frontServerUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        // 유저 정보 추출
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
        String memberEmail = customUserDetails.getEmail(); // 혹은 memberId를 로드하는 로직 필요

        // OAuth2User에는 DB의 memberId가 없을 수 있음.
        // 따라서 CustomOAuth2UserService에서 memberId를 attributes에 넣어두거나,
        // 여기서 이메일로 DB를 조회해서 memberId를 가져와야 함.
        // (여기서는 CustomOAuth2UserService에서 Role을 결정했던 로직을 활용)

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority(); // ROLE_MEMBER or ROLE_GUEST

        // *중요* : OAuth2User에 memberId가 없으므로, 이메일 기반으로 토큰을 만들거나
        // CustomOAuth2UserService에서 attributes에 memberId를 심어줬다고 가정해야 함.
        // 편의상 여기서는 임시 ID 0L 혹은 DB 조회 로직이 필요함.
        // (실무에서는 CustomOAuth2User에 memberId 필드를 추가해서 가져오는 것을 추천)
        Long memberId = 0L; // TODO: DB에서 조회하여 채울 것

        String accessToken = jwtUtil.createJwt(memberId, TokenKinds.ACCESS_TOKEN, role);
        String refreshToken = jwtUtil.createJwt(memberId, TokenKinds.REFRESH_TOKEN, role);

        // Refresh Token 저장 (Redis)
        refreshTokenRepository.save(new RefreshToken(refreshToken, memberId, role));

        // 리다이렉트 URL 생성 (프론트로 토큰 전달)
        // 주의: Access/Refresh 토큰을 URL에 노출하는 것은 보안상 취약할 수 있으나,
        // 도메인이 다른 경우(localhost:8080 <-> 8081) 쿠키 공유가 까다로워 이 방식을 사용하거나
        // '임시 코드'를 발급하고 프론트가 백엔드에 요청해서 토큰을 교환하는 방식(PKCE)을 씁니다.
        // 여기서는 가장 직관적인 '쿼리 파라미터 전달' 방식을 사용합니다.

        String targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl + "/login/oauth2/success")
                .queryParam("accessToken", accessToken)
                .queryParam("refreshToken", refreshToken)
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}