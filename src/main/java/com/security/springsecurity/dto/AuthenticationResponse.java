package com.security.springsecurity.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthenticationResponse {
    //private String username;
    private String token;
    private String email;

    public AuthenticationResponse(String token) {
        this.token = token;
    }
}
