package com.emma.Authentication.UserModel;

import com.emma.Authentication.enums.Roles;
import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;

import lombok.NoArgsConstructor;

import java.time.LocalDateTime;
import java.util.UUID;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="users")
public class UserModel {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name="username", nullable = false, updatable = false)
    private String username;

    @Column(name="email", nullable = false, updatable= false)
    private String email;

    @Column(name="password", nullable = false)
    private String password;

    @Column(name="google_id")
    private String googleId;

    @Enumerated(EnumType.STRING)
    private Roles role;

    @Column(name = "account_status", nullable = false)
    private Boolean enable= false;

    @Column(name="create_at", columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @Column(name="updated_at", columnDefinition = "TIMESTAMP DEFAULT CURRENT_TIMESTAMP", nullable = true, updatable = true)
    private LocalDateTime updatedAt;


    @PrePersist
    protected void onCreate() {

        createdAt = updatedAt = LocalDateTime.now();
    }

    @PreUpdate
    protected void onUpdate() {

        updatedAt = LocalDateTime.now();
    }


}
