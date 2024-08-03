package com.vid.VideoCall.Controller;

import com.vid.VideoCall.Entities.CustomUserDetails;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Jwt.JwtService;
import com.vid.VideoCall.RequestDTOs.ForgetPasswordRequest;
import com.vid.VideoCall.RequestDTOs.ResetPasswordRequest;
import com.vid.VideoCall.ResponseDTOs.UserResponse;
import com.vid.VideoCall.Service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.Date;
import java.util.List;

@RestController
@RequestMapping("/api/v1/users")
@CrossOrigin(origins = "*")
public class UserController {

    private final UserService userService;
    private final JwtService jwtService;

    public UserController(UserService userService, JwtService jwtService) {
        this.userService = userService;
        this.jwtService = jwtService;
    }

    @GetMapping("/me")
    public ResponseEntity<Object> authenticatedUser() {
        try {
//            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
//
//            if (authentication == null || !authentication.isAuthenticated() || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
//                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("User is not authenticated");
//            }
//
//            CustomUserDetails currentUserDetails = (CustomUserDetails) authentication.getPrincipal();
//            User currentUser = currentUserDetails.getUser();


            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            CustomUserDetails currentUserDetails = (CustomUserDetails) authentication.getPrincipal();
            User currentUser = currentUserDetails.getUser();

            UserResponse userResponse = UserResponse.builder()
                                        .userId(currentUser.getUserId())
                                        .userName(currentUser.getUserName())
                                        .emailId(currentUser.getEmailId())
                                        .updatedAt(currentUser.getUpdatedAt())
                                        .createdAt(currentUser.getCreatedAt())
                                        .status(currentUser.getStatus())
                                        .build();

            return ResponseEntity.status(HttpStatus.OK).body(userResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }


    @GetMapping("/getAll")
    public ResponseEntity<Object> findAll() {
        try {
            List<User> usersList = userService.findAll();
            return ResponseEntity.status(HttpStatus.OK).body(usersList);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @DeleteMapping("/delete")
    public ResponseEntity<Object> deleteUser(HttpServletRequest request) {
        try {
            // Get the current authenticated user
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
            CustomUserDetails currentUserDetails = (CustomUserDetails) authentication.getPrincipal();
            Integer userId = currentUserDetails.getUser().getUserId(); // Assuming `getUserId` returns the user ID

            // Extract the token from the request header
            String token = jwtService.extractTokenFromHeader(request);

            // If a token is present and not blacklisted, blacklist it
            if (token != null && !jwtService.isTokenBlacklisted(token)) {
                Date expirationDate = jwtService.extractExpiration(token);
                jwtService.blacklistToken(token, expirationDate);
            }

            // Delete the user account
            userService.deleteAccount(userId);

            // Clear the security context to ensure the user is logged out
            SecurityContextHolder.clearContext();

            return ResponseEntity.status(HttpStatus.OK).body("User account deleted successfully");
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }


//    @PostMapping("/forgot-password")
//    public ResponseEntity<Object> forgotPassword(@RequestBody ForgetPasswordRequest forgotPasswordRequest, @RequestBody HttpServletRequest httpServletRequest) {
//        try {
//            // Validate if email exists and send reset link with token
//            userService.generatePasswordResetToken(forgotPasswordRequest, httpServletRequest);
//            return ResponseEntity.status(HttpStatus.OK).body("Reset link sent successfully.");
//        } catch (IllegalArgumentException e) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
//        }
//    }

//    @PutMapping("/reset-password")
//    public ResponseEntity<Object> resetPassword(@RequestBody ResetPasswordRequest resetPasswordRequest) {
//        try {
//            // Validate token and update password
//            userService.resetPassword(resetPasswordRequest.getToken(), resetPasswordRequest.getNewPassword());
//            return ResponseEntity.status(HttpStatus.OK).body("Password reset successfully.");
//        } catch (IllegalArgumentException e) {
//            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
//        } catch (Exception e) {
//            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
//        }
//    }
}
