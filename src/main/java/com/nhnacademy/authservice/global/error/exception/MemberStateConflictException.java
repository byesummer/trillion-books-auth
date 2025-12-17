package com.nhnacademy.authservice.global.error.exception;

import com.nhnacademy.authservice.member.entity.MemberState;
import lombok.Getter;
import org.springframework.security.core.AuthenticationException;


@Getter
public class MemberStateConflictException extends AuthenticationException {
    private final MemberState state;

    public MemberStateConflictException(String msg, MemberState state) {
        super(msg);
        this.state = state;
    }
}
