package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.oauth2.CustomOAuth2User;
import com.nhnacademy.authservice.auth.dto.oauth2.GoogleResponse;
import com.nhnacademy.authservice.auth.dto.oauth2.OAuth2Response;
import com.nhnacademy.authservice.auth.dto.oauth2.PaycoResponse;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.entity.MemberRole;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import com.nhnacademy.authservice.global.error.exception.OAuthEmailNotFoundException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final MemberRepository memberRepository;
    private final PasswordEncoder passwordEncoder;

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

        if (existMember.isPresent()) {
            return new CustomOAuth2User(oAuth2Response, "ROLE_" + existMember.get().getMemberRole().name());
        } else {
            Member newMember = Member.builder()
                    .memberEmail(memberEmail)
                    .memberPassword(passwordEncoder.encode(UUID.randomUUID().toString()))
                    .memberName(oAuth2Response.getName())
                    .memberBirth(LocalDate.of(1000, 1, 1))
                    .memberContact(null)
                    .memberState(MemberState.ACTIVE)
                    .memberLatestLoginAt(LocalDate.now())
                    .memberRole(MemberRole.GUEST)
                    .memberPoint(0)
                    .memberAccumulateAmount(0)
                    .memberOauthId(oAuth2Response.getProviderId())
                    .gradeId(1L)
                    .build();

            memberRepository.save(newMember);

            return new CustomOAuth2User(oAuth2Response, "ROLE_GUEST");
        }
    }

    protected OAuth2User processOAuth2UserDelegate(OAuth2UserRequest request) {
        return super.loadUser(request);
    }
}
