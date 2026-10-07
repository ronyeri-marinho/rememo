package br.com.rememo.domain;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

public class User {
    private Long id;
    private UUID uuid;
    private String identityProviderId;
    private String firstName;
    private String lastName;
    private String email;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static User create(String identityProviderId,
                              String firstName,
                              String lastName,
                              String email) {
        User user = new User();
        user.setUuid(UUID.randomUUID());
        user.setIdentityProviderId(identityProviderId);
        user.setFirstName(firstName);
        user.setLastName(lastName);
        user.setEmail(email);
        user.setCreatedAt(LocalDateTime.now());
        user.setUpdatedAt(LocalDateTime.now());
        return user;
    }

    public boolean updateFirstName(String firstName) {
        if (firstName != null && !firstName.isBlank() && !Objects.equals(this.firstName, firstName)) {
            this.firstName = firstName;
            return true;
        }
        return false;
    }

    public boolean updateLastName(String lastName) {
        if (lastName != null && !lastName.isBlank() && !Objects.equals(this.lastName, lastName)) {
            this.lastName = lastName;
            return true;
        }
        return false;
    }

    public boolean updateEmail(String email) {
        if (email != null && !email.isBlank() && !Objects.equals(this.email, email)) {
            this.email = email;
            return true;
        }
        return false;
    }

    public void markUpdated() {
        this.setUpdatedAt(LocalDateTime.now());
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public UUID getUuid() {
        return uuid;
    }

    public void setUuid(UUID uuid) {
        this.uuid = uuid;
    }

    public String getIdentityProviderId() {
        return identityProviderId;
    }

    public void setIdentityProviderId(String identityProviderId) {
        this.identityProviderId = identityProviderId;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(LocalDateTime updatedAt) {
        this.updatedAt = updatedAt;
    }
}
