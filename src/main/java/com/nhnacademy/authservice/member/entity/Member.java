package com.nhnacademy.authservice.member.entity;

import com.nhnacademy.authservice.global.error.exception.MemberStateConflictException;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDate;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "member")
@Getter
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

    @Setter
    @Column(name = "member_name", length = 255)
    private String memberName;

    @Setter
    @Column(name = "member_contact", unique = true, length = 255)
    private String memberContact;

    @Setter
    @Column(name = "member_birth", nullable = false)
    private LocalDate memberBirth;

    @Setter
    @Column(name = "member_state", nullable = false)
    @Enumerated(EnumType.STRING)
    private MemberState memberState;

    @Setter
    @Column(name = "member_latest_login_at", nullable = false)
    private LocalDate memberLatestLoginAt;

    @Setter
    @Column(name = "member_role", nullable = false)
    @Enumerated(EnumType.STRING)
    private MemberRole memberRole;

    @Column(name = "member_point", nullable = false)
    private Integer memberPoint;

    @Column(name = "member_accumulate_amount", nullable = false)
    private Integer memberAccumulateAmount;

    @Column(name = "member_oauth_id", length = 255)
    private String memberOauthId;

    @Column(name = "grade_id", nullable = false)
    private Long gradeId;

    public void validateActive() {
        if (getMemberState() == MemberState.DORMANT) {
            throw new MemberStateConflictException("휴면 계정입니다. 인증이 필요합니다.", MemberState.DORMANT);
        }

        if (getMemberState() == MemberState.WITHDRAWAL) {
            throw new MemberStateConflictException("탈퇴한 회원입니다.", MemberState.WITHDRAWAL);
        }
    }
}