package br.com.rememo.domain.deck;

import br.com.rememo.domain.user.User;

import java.time.LocalDateTime;
import java.util.UUID;

public class Deck {
    private Long id;
    private UUID uuid;
    private String name;
    private String description;
    private User user;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static Deck create(String name,
                              String description,
                              User user) {
        Deck deck = new Deck();
        deck.setUuid(UUID.randomUUID());
        deck.setName(name);
        deck.setDescription(description);
        deck.setUser(user);
        deck.setCreatedAt(LocalDateTime.now());
        deck.setUpdatedAt(LocalDateTime.now());
        return deck;
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

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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
