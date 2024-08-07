package com.vid.VideoCall.Service;

import com.vid.VideoCall.Entities.RefreshToken;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Repository.RefreshTokenRepository;
import com.vid.VideoCall.Jwt.JwtService;
import com.vid.VideoCall.Entities.CustomUserDetails;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.NoSuchElementException;
import java.util.Optional;

@Slf4j
@Service
public class RefreshTokenService {
    @Value("${app.jwt.refresh-token-expiration}")
    private long refreshTokenExpiration;

    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    @Transactional
    public String createNewRefreshToken(User user) {
        // Generate a new refresh token
        SecureRandom secureRandom = new SecureRandom();
        byte[] refreshTokenBytes = new byte[32]; // 256 bits
        secureRandom.nextBytes(refreshTokenBytes);

        String token = Base64.getUrlEncoder().withoutPadding().encodeToString(refreshTokenBytes);

        RefreshToken refreshToken = user.getRefreshToken();

        if (refreshToken == null) {
            // Create a new RefreshToken entity if it does not exist
            refreshToken = RefreshToken.builder()
                    .user(user)
                    .token(token)
                    .expiryDate(new Date(System.currentTimeMillis() + refreshTokenExpiration))
                    .build();
        } else {
            // Update the existing RefreshToken entity
            refreshToken.setToken(token);
            refreshToken.setExpiryDate(new Date(System.currentTimeMillis() + refreshTokenExpiration));
        }

        // Save the refresh token to the database
        refreshTokenRepository.save(refreshToken);

        return token;
    }


    public boolean validateToken(String token) {
        return refreshTokenRepository.findByToken(token)
                .map(refreshToken -> {
                    // Check if the token is expired
                    if (refreshToken.getExpiryDate().before(new Date())) {
                        // Token has expired, delete it from the database
                        deleteToken(refreshToken);
                        return false;
                    }
                    // Token is still valid
                    return true;
                })
                .orElse(false); // Token does not exist
    }


    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    @Transactional
    public String refreshAccessToken(String refreshToken, JwtService jwtService) {
        if (validateToken(refreshToken)) {
            RefreshToken tokenEntity = findByToken(refreshToken).orElseThrow(()-> new NoSuchElementException("Token Not Found"));
            User user = tokenEntity.getUser();
            return jwtService.generateToken(new CustomUserDetails(user));
        }
        throw new IllegalArgumentException("Invalid or expired refresh token");
    }

    public void deleteToken(RefreshToken refreshToken) {
        refreshTokenRepository.delete(refreshToken);
    }
}
