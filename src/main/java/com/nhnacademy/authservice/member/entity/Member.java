package com.nhnacademy.authservice.member.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDate;

@Entity
@Table(name = "member")
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id")
    private Long memberId;

    @Column(name = "member_email", nullable = false, unique = true, length = 255)
    private String memberEmail;

    @Column(name = "member_password", nullable = false, length = 255)
    private String memberPassword;

    @Column(name = "member_state", nullable = false)
    @Enumerated(EnumType.STRING)
    private MemberState memberState;

    @Column(name = "member_latest_login_at", nullable = false)
    private LocalDate memberLatestLoginAt;

    @Column(name = "member_role", nullable = false)
    @Enumerated(EnumType.STRING)
    private MemberRole memberRole;

    @Column(name = "member_oauth_id", length = 255)
    private String memberOauthId;

    public static Member createForAuthentication(Long memberId, MemberRole role){
        Member member = new Member();
        member.setMemberId(memberId);
        member.setMemberEmail("jwt@temp.com"); // 사용되지 않을 임시 이메일
        member.setMemberPassword("temppassword"); // 사용되지 않을 임시 비밀번호
        member.setMemberRole(role);
        return member;
    }

}