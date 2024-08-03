package com.vid.VideoCall.Service;

import com.vid.VideoCall.Entities.PasswordReset;
import com.vid.VideoCall.Entities.User;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class EmailService {
    private final JavaMailSender javaMailSender;

    public EmailService(JavaMailSender javaMailSender) {
        this.javaMailSender = javaMailSender;
    }

    public void sendPasswordResetEmail(User user, PasswordReset passwordReset) {
        SimpleMailMessage mailMessage = new SimpleMailMessage();
        mailMessage.setTo(user.getEmailId());
        mailMessage.setSubject("Password Reset Request");
        mailMessage.setText("To reset your password, click the link below:\n\n"
                + "http://localhost:8080//api/v1/users/reset-password?token=" + passwordReset.getResetToken());

        javaMailSender.send(mailMessage);
    }
}
