package com.vid.VideoCall.Service;

import com.vid.VideoCall.Entities.CustomUserDetails;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Enums.Status;
import com.vid.VideoCall.Jwt.JwtService;
import com.vid.VideoCall.Repository.UserRepository;
import com.vid.VideoCall.RequestDTOs.AddUserRequest;
import com.vid.VideoCall.RequestDTOs.UserLoginRequest;
import com.vid.VideoCall.ResponseDTOs.LoginResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

    private final UserRepository userRepository;
    private final BCryptPasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthenticationService(UserRepository userRepository, BCryptPasswordEncoder passwordEncoder, AuthenticationManager authenticationManager, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

        public LoginResponse registerAndLogin(AddUserRequest addUserRequest) throws Exception {
            validatePassword(addUserRequest.getPassword());

            String hashedPassword = passwordEncoder.encode(addUserRequest.getPassword());
            User user = User.builder()
                    .userName(addUserRequest.getUserName())
                    .emailId(addUserRequest.getEmailId())
                    .password(hashedPassword)
                    .status(Status.ACTIVE)
                    .build();
            return generateLoginResponse(userRepository.save(user));
        }

    private void validatePassword(String password) {
        if (!password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@#$%^&+=!*])(?!.*\\s)[A-Za-z\\d@#$%^&+=!*]{8,}$")) {
            throw new IllegalArgumentException("Password must have minimum eight characters, at least one uppercase letter, one lowercase letter, one number, one special character (@#$%^&+=!*), and no whitespace");
        }
    }

    public LoginResponse login(UserLoginRequest userLoginRequest) throws Exception {
        // Authenticate user
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        userLoginRequest.getEmailId(),
                        userLoginRequest.getPassword()
                )
        );

        // Fetch the user from the repository
        User user = userRepository.findByEmailId(userLoginRequest.getEmailId())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        // Generate and return the login response
        return generateLoginResponse(user);
    }

    private LoginResponse generateLoginResponse(User user) {
        CustomUserDetails customUserDetails = new CustomUserDetails(user);
        String accessToken = jwtService.generateToken(customUserDetails);
        String refreshToken = refreshTokenService.createNewRefreshToken(user);

        return LoginResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .expiresIn(jwtService.getExpirationTime())
                .build();
    }
}
