package com.vid.VideoCall.Repository;

import com.vid.VideoCall.Entities.PasswordReset;
import com.vid.VideoCall.Entities.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface PasswordResetTokenRepository extends JpaRepository<PasswordReset,Integer> {
    Optional<PasswordReset> findByResetTokenAndUser(String token, User user);

    PasswordReset findByResetToken(String token);
}
