package br.com.rememo.application.deck.usecase;

import br.com.rememo.application.deck.transport.CreateDeckDTO;
import br.com.rememo.domain.deck.Deck;

public interface CreateDeckUseCase {

    Deck create(CreateDeckDTO createDeckDTO);
}
