package com.vid.VideoCall.RequestDTOs;

import lombok.Data;

@Data
public class ResetPasswordRequest {
    private String token;

    private String newPassword;
}
