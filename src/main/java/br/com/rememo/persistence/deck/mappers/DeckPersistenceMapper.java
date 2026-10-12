package br.com.rememo.persistence.deck.mappers;

import br.com.rememo.domain.deck.Deck;
import br.com.rememo.persistence.deck.DeckEntity;
import br.com.rememo.persistence.user.UserEntity;
import br.com.rememo.persistence.user.mappers.UserPersistenceMapper;

public class DeckPersistenceMapper {

    private DeckPersistenceMapper() {

    }

    public static Deck toDomain(DeckEntity deckEntity) {
        Deck deck = new Deck();
        deck.setId(deckEntity.getId());
        deck.setUuid(deckEntity.getUuid());
        deck.setName(deckEntity.getName());
        deck.setDescription(deckEntity.getDescription());
        deck.setCreatedAt(deckEntity.getCreatedAt());
        deck.setUpdatedAt(deckEntity.getUpdatedAt());
        deck.setUser(UserPersistenceMapper.toDomain(deckEntity.getUser()));
        return deck;
    }

    public static DeckEntity toEntity(Deck deck, UserEntity user) {
        DeckEntity deckEntity = new DeckEntity();
        deckEntity.setId(deck.getId());
        deckEntity.setUuid(deck.getUuid());
        deckEntity.setName(deck.getName());
        deckEntity.setDescription(deck.getDescription());
        deckEntity.setCreatedAt(deck.getCreatedAt());
        deckEntity.setUpdatedAt(deck.getUpdatedAt());
        deckEntity.setUser(user);
        return deckEntity;
    }
}
