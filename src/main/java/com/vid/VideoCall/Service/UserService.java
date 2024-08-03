package com.vid.VideoCall.Service;

import com.vid.VideoCall.Entities.PasswordReset;
import com.vid.VideoCall.Entities.User;
import com.vid.VideoCall.Repository.PasswordResetTokenRepository;
import com.vid.VideoCall.Repository.UserRepository;
import com.vid.VideoCall.RequestDTOs.ForgetPasswordRequest;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Date;
import java.util.List;

@Service
@Slf4j
public class UserService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final PasswordResetTokenService passwordResetTokenService;

    public UserService(UserRepository userRepository, PasswordResetTokenRepository passwordResetTokenRepository, PasswordEncoder passwordEncoder, PasswordResetTokenService passwordResetTokenService) {
        this.userRepository = userRepository;
        this.passwordResetTokenRepository = passwordResetTokenRepository;
        this.passwordEncoder = passwordEncoder;
        this.passwordResetTokenService = passwordResetTokenService;
    }

    public List<User> findAll() {
        return userRepository.findAll();
    }

    @Transactional
    public void deleteAccount(Integer userId) {
        if (!userRepository.existsById(userId)) {
            throw new IllegalArgumentException("User not found with id: " + userId);
        }
        userRepository.deleteById(userId);
        log.info("User with id {} deleted successfully.", userId);
    }

    public void generatePasswordResetToken(ForgetPasswordRequest forgetPasswordRequest, HttpServletRequest httpServletRequest) throws Exception {
        User user = userRepository.findByEmailId(forgetPasswordRequest.getEmailId())
                .orElseThrow(() -> new IllegalArgumentException("User not found with email: " + forgetPasswordRequest.getEmailId()));
        passwordResetTokenService.createToken(user, httpServletRequest);
    }

    public void resetPassword(String token, String newPassword) {
        PasswordReset passwordReset = passwordResetTokenRepository.findByResetToken(token);
        if (passwordReset == null || passwordReset.getExpiryDate().before(new Date()) || passwordReset.getUsed()) {
            throw new IllegalArgumentException("Invalid or expired token");
        }
        User user = passwordReset.getUser();
        user.setPassword(passwordEncoder.encode(newPassword));
        userRepository.save(user);
        passwordReset.setUsed(true);
        passwordResetTokenRepository.save(passwordReset);
    }
}
