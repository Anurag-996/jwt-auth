package com.vid.VideoCall.Entities;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.UpdateTimestamp;
import java.util.Date;
import java.util.List;

@Entity
@Table(name = "password_reset")
@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class PasswordReset {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @UpdateTimestamp
    private Date lastUpdated;

    @ElementCollection
    @CollectionTable(name = "password_reset_attempt", joinColumns = @JoinColumn(name = "password_reset_id"))
    @Column(name = "attempt_date")
    private List<Date> resetAttempts;

    @Column(name = "reset_token")
    private String resetToken;

    @Column(name = "expiry_date")
    private Date expiryDate;

    @Column(name = "is_used",columnDefinition = "TINYINT(1)")
    private Boolean used;

    @Column(name = "request_ip")
    private String requestIpAddress;

    @Column(name = "request_timestamp")
    private Date requestTimestamp;

    @OneToOne
    @JoinColumn(name = "user_id")
    private User user;
}
