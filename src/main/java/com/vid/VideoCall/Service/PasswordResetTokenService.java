package com.vid.VideoCall.Service;

import com.vid.VideoCall.Entities.PasswordReset;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Repository.PasswordResetTokenRepository;
import com.vid.VideoCall.Repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Service
public class PasswordResetTokenService {

    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    
    public PasswordResetTokenService(PasswordResetTokenRepository passwordResetTokenRepository, UserRepository userRepository, EmailService emailService) {
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.userRepository = userRepository;
        this.emailService = emailService;
    }

    @Transactional
    public String createToken(User user, String requestIpAddress) {
        String token = generateToken();
        PasswordReset resetToken = PasswordReset.builder()
                .resetToken(token)
                .user(user)
                .expiryDate(new Date(System.currentTimeMillis() + 15 * 60 * 1000)) // 15 minutes expiry
                .requestIpAddress(requestIpAddress) // Set the client's IP address
                .requestTimestamp(new Date(System.currentTimeMillis()))
                .build();

        user.setPasswordReset(resetToken);
        userRepository.save(user);
        return token;
    }


    @Transactional
    public String createToken(User user, HttpServletRequest request) throws IllegalAccessException {
        PasswordReset existingToken = user.getPasswordReset();

        if (existingToken != null && new Date().before(existingToken.getExpiryDate()) && !existingToken.getUsed()) {
            throw new IllegalAccessException("Email already sent");
        }

        String clientIpAddress = getClientIpAddress(request);
        return createToken(user, clientIpAddress);
    }

    public String generateToken() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] tokenBytes = new byte[32];
        secureRandom.nextBytes(tokenBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(tokenBytes);
    }



    public PasswordReset validateToken(String token,User user) {
        Optional<PasswordReset> resetTokenOptional = passwordResetTokenRepository.findByResetTokenAndUser(token, user);

        if (resetTokenOptional.isPresent()) {
            PasswordReset resetToken = resetTokenOptional.get();
            if (!new Date().after(resetToken.getExpiryDate()) && !resetToken.getUsed()) {
                return resetToken;
            }
        }
        return null;
    }

    public void markAsUsed(PasswordReset resetToken) {
        resetToken.setUsed(true);
        passwordResetTokenRepository.save(resetToken);
    }


    private String getClientIpAddress(HttpServletRequest request) {
        String ipAddress = request.getHeader("X-Forwarded-For");
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_FORWARDED");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_X_CLUSTER_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_FORWARDED_FOR");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getHeader("HTTP_FORWARDED");
        }
        if (ipAddress == null || ipAddress.isEmpty() || "unknown".equalsIgnoreCase(ipAddress)) {
            ipAddress = request.getRemoteAddr();
        }
        return ipAddress;
    }
}
