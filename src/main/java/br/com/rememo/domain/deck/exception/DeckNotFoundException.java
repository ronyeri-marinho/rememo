package br.com.rememo.domain.deck.exception;

import br.com.rememo.domain.common.exception.NotFoundException;

import java.util.UUID;

public class DeckNotFoundException extends NotFoundException {

    public DeckNotFoundException(UUID uuid) {
        super("Deck not found: " + uuid);
    }

    public DeckNotFoundException(UUID uuid, UUID userId) {
        super(String.format(
                "Deck not found for user. deckId=%s, userId=%s", uuid, userId
        ));
    }
}
