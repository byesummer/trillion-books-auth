package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.dto.oauth2.GoogleResponse;
import com.nhnacademy.authservice.auth.dto.oauth2.OAuth2Response;
import com.nhnacademy.authservice.auth.dto.oauth2.PaycoResponse;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import com.nhnacademy.authservice.global.error.exception.OAuthEmailNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;

    public CustomOAuth2UserService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    // Spring Security의 loadUser Override
    @Override
    public OAuth2User loadUser(OAuth2UserRequest request) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = processOAuth2UserDelegate(request);
        String registrationId = request.getClientRegistration().getRegistrationId();

        OAuth2Response oAuth2Response;
        if(registrationId.equals("google")){
            oAuth2Response = new GoogleResponse(oAuth2User.getAttributes());
        }else if (registrationId.equals("payco")){
            oAuth2Response = new PaycoResponse(oAuth2User.getAttributes());
        } else {
            // 해당하는 provider가 없음
            return null;
        }
        String memberEmail = oAuth2Response.getEmail();
        if (memberEmail == null || memberEmail.isBlank()) {
            throw new OAuthEmailNotFoundException("이메일을 찾을 수 없습니다.");
        }

        // DB에서 이메일로 조회
        Optional<Member> existMember = memberRepository.findByMemberEmail(memberEmail);

        // 이미 가입된 회원: ROLE_MEMBER
        // 신규 회원: 아직 DB 저장 안 한 상태, ROLE_GUEST
        return existMember.map(member -> new CustomOAuth2User(oAuth2Response, "ROLE_" + member.getMemberRole().name())).orElseGet(() -> new CustomOAuth2User(oAuth2Response, "ROLE_GUEST"));
    }

    protected OAuth2User processOAuth2UserDelegate(OAuth2UserRequest request) {
        return super.loadUser(request);
    }
}
