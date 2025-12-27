package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.entity.RefreshToken;
import com.nhnacademy.authservice.auth.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.global.error.exception.MemberNotFoundException;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.repository.MemberRepository;
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
    private final MemberRepository memberRepository;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;

    // 프론트 서버 주소
    @Value("${front.server.url:http://localhost:10402}")
    private String frontServerUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        // 유저 정보 추출
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
        String memberEmail = customUserDetails.getEmail(); // 혹은 memberId를 로드하는 로직 필요

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String role = auth.getAuthority(); // ROLE_MEMBER or ROLE_GUEST

        Member member = memberRepository.findByMemberEmail(memberEmail)
                .orElseThrow(() -> new MemberNotFoundException("회원 정보를 찾을 수 없습니다."));

        Long memberId = member.getMemberId();

        String accessToken = jwtUtil.createJwt(memberId, TokenKinds.ACCESS_TOKEN, role);
        String refreshToken = jwtUtil.createJwt(memberId, TokenKinds.REFRESH_TOKEN, role);

        // Refresh Token 저장 (Redis)
        refreshTokenRepository.save(new RefreshToken(refreshToken, memberId, role));

        String targetUrl;

        String memberOauthId = member.getMemberOauthId();

        // 권한에 따른 리다이렉트 분기
        if ("ROLE_GUEST".equals(role)) {
            // 신규 회원이면 -> 추가 정보 입력 페이지로 이동
            targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/members/social-signup")
                    .queryParam("accessToken", accessToken)
                    .queryParam("refreshToken", refreshToken)
                    .queryParam("memberOauthId", memberOauthId)
                    .build().toUriString();
        } else {
            // 기존 회원이면 -> 로그인 성공 처리 (메인 페이지)
            targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/login/oauth2/success")
                    .queryParam("accessToken", accessToken)
                    .queryParam("refreshToken", refreshToken)
                    .build().toUriString();
        }
        clearAuthenticationAttributes(request, response);

        response.sendRedirect(targetUrl);
    }

    protected void clearAuthenticationAttributes(HttpServletRequest request, HttpServletResponse response) {
        super.clearAuthenticationAttributes(request);
        authorizationRequestRepository.removeAuthorizationRequestCookies(request, response);
    }
}