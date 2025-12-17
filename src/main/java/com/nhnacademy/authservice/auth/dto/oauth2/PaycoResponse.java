package com.nhnacademy.authservice.auth.dto.oauth2;

import java.util.Map;

public class PaycoResponse implements OAuth2Response{
    private final Map<String, Object> attribute;

    public PaycoResponse(Map<String, Object> allAttributes) {
        Map<String, Object> data = (Map<String, Object>) allAttributes.get("data");
        this.attribute = (Map<String, Object>) data.get("member");
    }

    @Override
    public String getProvider() { return "payco"; }
    @Override
    public String getProviderId() { return attribute.get("idNo").toString(); }
    @Override
    public String getEmail() {
        Object emailValue = attribute.get("email");
        return (emailValue != null) ? emailValue.toString() : null;
    }
    @Override
    public String getName() { Object emailValue = attribute.get("name");
        return (emailValue != null) ? emailValue.toString() : null;
    }

    // 생년월일, 연락처, 주소는 바로가입 서비스를 통해 가져온 값으로, 미동의 시 null값으로 받아옴.
    public String getBirthday() {
        Object birthdayValue = attribute.get("birthday");
        return (birthdayValue != null) ? birthdayValue.toString() : null;
    }
    public String getContactNumber() {
        Object contactValue = attribute.get("contactNumber");
        return (contactValue != null) ? contactValue.toString() : null;
    }
    // Payco에서 Object 타입으로 넘겨주므로 Map으로 반환하고 MemberService에서 AddressCreateRequest로 변환.
    public Map<String,Object> getAddress() {
        Object address = attribute.get("address");
        if (address instanceof Map) {
            return (Map<String, Object>) address;
        }
        return null;
    }
}
