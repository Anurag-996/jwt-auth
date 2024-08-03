package com.vid.VideoCall.ResponseDTOs;

import com.vid.VideoCall.Enums.Status;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Date;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserResponse {
    private Integer userId;

    private String emailId;

    private String userName;

    private Status status;

    private Date createdAt;

    private Date updatedAt;


}
