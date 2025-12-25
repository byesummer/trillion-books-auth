package com.nhnacademy.authservice.member.entity;

import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MemberTest {
    @Test
    @DisplayName("멤버가 액티브이면 예외를 반환하지않음.")
    void validateToken() {
        Member member = Member.builder().build();
        member.setMemberState(MemberState.ACTIVE);
        Assertions.assertThatCode(()->member.validateActive()).doesNotThrowAnyException();
    }
    @Test
    @DisplayName("멤버가 액티브가아니면 예외를 반환한다.")
    void validateToken1() {
        Member member = Member.builder().build();

        Assertions.assertThatThrownBy(()->{
            member.setMemberState(MemberState.DORMANT);
            member.validateActive();
        }).isInstanceOf(RuntimeException.class);
    }
    @Test
    @DisplayName("멤버가 액티브가아니면 예외를 반환한다.")
    void validateToken2() {
        Member member = Member.builder().build();

        Assertions.assertThatThrownBy(()->{
            member.setMemberState(MemberState.WITHDRAWAL);
            member.validateActive();
        }).isInstanceOf(RuntimeException.class);
    }
}