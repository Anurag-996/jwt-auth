package com.vid.VideoCall.Controller;

import com.vid.VideoCall.Entities.CustomUserDetails;
import com.vid.VideoCall.Entities.RefreshToken;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Jwt.JwtService;
import com.vid.VideoCall.RequestDTOs.AddUserRequest;
import com.vid.VideoCall.RequestDTOs.RefreshTokenRequestDTO;
import com.vid.VideoCall.RequestDTOs.UserLoginRequest;
import com.vid.VideoCall.ResponseDTOs.LoginResponse;
import com.vid.VideoCall.Service.AuthenticationService;
import com.vid.VideoCall.Service.RefreshTokenService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Date;

@RestController
@RequestMapping("/auth")
public class AuthenticationController {

    private final AuthenticationService authenticationService;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthenticationController(AuthenticationService authenticationService, JwtService jwtService,
            RefreshTokenService refreshTokenService) {
        this.authenticationService = authenticationService;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/signup")
    public ResponseEntity<Object> register(@RequestBody AddUserRequest addUserRequest) {
        try {
            LoginResponse loginResponse = authenticationService.registerAndLogin(addUserRequest);
            return ResponseEntity.status(HttpStatus.OK).body(loginResponse);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/login")
    public ResponseEntity<Object> login(@RequestBody UserLoginRequest userLoginRequest) {
        try {
            LoginResponse loginResponse = authenticationService.login(userLoginRequest);
            return ResponseEntity.status(HttpStatus.OK).body(loginResponse);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<Object> refreshToken(@RequestBody RefreshTokenRequestDTO refreshTokenRequestDTO) {
        try {
            String newAccessToken = refreshTokenService.refreshAccessToken(refreshTokenRequestDTO.getToken(),
                    jwtService);

            LoginResponse loginResponse = LoginResponse.builder()
                    .accessToken(newAccessToken)
                    .refreshToken(refreshTokenRequestDTO.getToken())
                    .expiresIn(jwtService.getExpirationTime())
                    .build();

            return ResponseEntity.status(HttpStatus.OK).body(loginResponse);
        } catch (IllegalArgumentException e) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(e.getMessage());
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(e.getMessage());
        }
    }

    @PostMapping("/logout")
    public ResponseEntity<Object> logout(HttpServletRequest request) {
        // Check for the presence of the Authorization header
        String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader == null || authorizationHeader.isEmpty()) {
            throw new RuntimeException("Authorization token is missing.");
        }

        // Extract the access token from the request header
        String accessToken = jwtService.extractTokenFromHeader(request);

        // Get the current authenticated user
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !(authentication.getPrincipal() instanceof CustomUserDetails)) {
            throw new RuntimeException("User is not authenticated.");
        }

        // Extract user details
        CustomUserDetails currentUserDetails = (CustomUserDetails) authentication.getPrincipal();
        User user = currentUserDetails.getUser(); // Assuming CustomUserDetails has a getUser() method

        // Retrieve the refresh token associated with the user
        RefreshToken refreshToken = user.getRefreshToken();

        // Blacklist the access token if present
        if (accessToken != null) {
            if (jwtService.isTokenBlacklisted(accessToken)) {
                throw new IllegalStateException("Access token is already blacklisted");
            }

            // Blacklist the access token
            Date expirationDate = jwtService.extractExpiration(accessToken);
            jwtService.blacklistToken(accessToken, expirationDate);
        }

        // Delete the refresh token from the database if it exists
        if (refreshToken != null) {
            refreshTokenService.deleteToken(refreshToken);
        }

        // Clear the security context to fully log out the user
        SecurityContextHolder.clearContext();

        // Return a success response
        return ResponseEntity.status(HttpStatus.OK).body("Logout successful");
    }

}
