package com.nhnacademy.authservice.auth.jwt;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.nhnacademy.authservice.auth.repository.RefreshTokenRepository;
import com.nhnacademy.authservice.auth.service.OAuth2CodeService;
import com.nhnacademy.authservice.global.error.exception.MemberNotFoundException;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.util.Collection;
import java.util.Iterator;

@Component
@RequiredArgsConstructor
public class SocialLoginHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtUtil jwtUtil;
    private final RefreshTokenRepository refreshTokenRepository;
    private final MemberRepository memberRepository;
    private final HttpCookieOAuth2AuthorizationRequestRepository authorizationRequestRepository;
    private final OAuth2CodeService oAuth2CodeService;

    // 프론트 서버 주소
    @Value("${front.server.url:http://localhost:10402}")
    private String frontServerUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {

        // 유저 정보 추출
        CustomOAuth2User customUserDetails = (CustomOAuth2User) authentication.getPrincipal();
        String memberEmail = customUserDetails.getEmail();

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        Iterator<? extends GrantedAuthority> iterator = authorities.iterator();
        GrantedAuthority auth = iterator.next();
        String memberStatus = auth.getAuthority(); // ROLE_MEMBER or ROLE_GUEST

        Member member = memberRepository.findByMemberEmail(memberEmail)
                .orElseThrow(() -> new MemberNotFoundException("회원 정보를 찾을 수 없습니다."));

        if (member.getMemberState() == MemberState.DORMANT) {
            String targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/members/dormant")
                    .build().toUriString();

            clearAuthenticationAttributes(request, response);
            response.sendRedirect(targetUrl);
            return;
        }

        if (member.getMemberState() == MemberState.WITHDRAWAL) {
            String targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/login")
                    .queryParam("error", "withdrawal")
                    .build().toUriString();

            clearAuthenticationAttributes(request, response);
            response.sendRedirect(targetUrl);
            return;
        }

        Long memberId = member.getMemberId();
        String memberRole = member.getMemberRole().toString();
        String memberOauthId = member.getMemberOauthId();
        String targetUrl;

        String code = oAuth2CodeService.issueCode(memberId, memberRole);

        if ("ROLE_GUEST".equals(memberStatus)) {
            targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/members/social-signup")
                    .queryParam("code", code)
                    .queryParam("memberOauthId", memberOauthId)
                    .build().toUriString();
        } else {
            targetUrl = UriComponentsBuilder.fromUriString(frontServerUrl)
                    .path("/login/oauth2/success")
                    .queryParam("code", code)
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