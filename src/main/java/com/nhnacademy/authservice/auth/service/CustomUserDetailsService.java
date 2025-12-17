package com.nhnacademy.authservice.auth.service;

import com.nhnacademy.authservice.auth.dto.CustomUserDetails;
import com.nhnacademy.authservice.member.entity.Member;
import com.nhnacademy.authservice.member.entity.MemberState;
import com.nhnacademy.authservice.member.repository.MemberRepository;
import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final MemberRepository memberRepository;

    public CustomUserDetailsService(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }


    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        Member memberData = memberRepository.findByMemberEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException("사용자를 찾을 수 없습니다: " + username));

        // 휴면 계정 체크
        // 로그인 시 휴면 계정이나 탈퇴 회원 경우 MemberStateConflictException를 던져 AuthController에서 처리
        if (memberData.getMemberState() == MemberState.DORMANT) {
            throw new MemberStateConflictException("휴면 계정입니다. 인증이 필요합니다.", MemberState.DORMANT);
        }

        // 탈퇴한 회원 체크
        if (memberData.getMemberState() == MemberState.WITHDRAWAL) {
            throw new MemberStateConflictException("탈퇴한 회원입니다.", MemberState.WITHDRAWAL);
        }

        // MemberState가 ACTIVE인 경우에만 UserDetails 생성
        return new CustomUserDetails(memberData);
    }
}
