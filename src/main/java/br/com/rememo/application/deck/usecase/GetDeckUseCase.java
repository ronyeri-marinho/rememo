package br.com.rememo.application.deck.usecase;

import br.com.rememo.domain.deck.Deck;

import java.util.UUID;

public interface GetDeckUseCase {

    Deck getDeckByUuid(UUID uuid);
}
