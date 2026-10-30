package br.com.rememo.domain.flashcard;

import br.com.rememo.domain.deck.Deck;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.UUID;

public class Flashcard {
    private Long id;
    private UUID uuid;
    private String question;
    private String answer;
    private Deck deck;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;

    public static Flashcard create(String question,
                                   String answer,
                                   Deck deck) {
        Flashcard flashcard = new Flashcard();
        flashcard.setUuid(UUID.randomUUID());
        flashcard.setQuestion(question);
        flashcard.setAnswer(answer);
        flashcard.setDeck(deck);
        flashcard.setCreatedAt(LocalDateTime.now());
        flashcard.setUpdatedAt(LocalDateTime.now());
        return flashcard;
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

    public String getQuestion() {
        return question;
    }

    public void setQuestion(String question) {
        this.question = question;
    }

    public String getAnswer() {
        return answer;
    }

    public void setAnswer(String answer) {
        this.answer = answer;
    }

    public Deck getDeck() {
        return deck;
    }

    public void setDeck(Deck deck) {
        this.deck = deck;
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

    @Override
    public boolean equals(Object request) {
        if (request == null || getClass() != request.getClass()) return false;
        Flashcard flashcard = (Flashcard) request;
        return Objects.equals(id, flashcard.id) && Objects.equals(uuid, flashcard.uuid);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, uuid);
    }
}
