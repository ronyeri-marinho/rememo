package br.com.rememo.application.deck;

import br.com.rememo.application.deck.usecase.GetDeckUseCase;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.deck.exception.DeckNotFoundException;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import org.springframework.stereotype.Service;

import java.util.UUID;

@Service
public class GetDeckService implements GetDeckUseCase {
    private final GetUserInSessionUseCase getUserInSessionUseCase;
    private final DeckRepositoryPort deckRepositoryPort;

    public GetDeckService(GetUserInSessionUseCase getUserInSessionUseCase,
                          DeckRepositoryPort deckRepositoryPort) {
        this.getUserInSessionUseCase = getUserInSessionUseCase;
        this.deckRepositoryPort = deckRepositoryPort;
    }

    @Override
    public Deck getDeckByUuid(UUID uuid) {
        User userInSession = this.getUserInSessionUseCase.getUserInSession();
        return this.deckRepositoryPort.findByUuidAndUserId(uuid, userInSession.getId())
                .orElseThrow(() -> new DeckNotFoundException(uuid, userInSession.getUuid()));
    }
}
