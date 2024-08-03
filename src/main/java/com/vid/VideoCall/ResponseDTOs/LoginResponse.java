package com.vid.VideoCall.ResponseDTOs;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class LoginResponse {
    private String accessToken;

    private String refreshToken;

    private long expiresIn; // Expiration time for the access token, in milliseconds
}
