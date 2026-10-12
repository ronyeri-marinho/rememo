package br.com.rememo.application.deck;

import br.com.rememo.application.deck.transport.CreateDeckDTO;
import br.com.rememo.application.deck.usecase.CreateDeckUseCase;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class CreateDeckService implements CreateDeckUseCase {

    private static final Logger LOGGER = LoggerFactory.getLogger(CreateDeckService.class);
    private final GetUserInSessionUseCase getUserInSessionUseCase;
    private final DeckRepositoryPort deckRepositoryPort;

    public CreateDeckService(GetUserInSessionUseCase getUserInSessionUseCase,
                             DeckRepositoryPort deckRepositoryPort) {
        this.getUserInSessionUseCase = getUserInSessionUseCase;
        this.deckRepositoryPort = deckRepositoryPort;
    }

    @Override
    @Transactional
    public Deck create(CreateDeckDTO createDeckDTO) {
        User userInSession = this.getUserInSessionUseCase.getUserInSession();

        Deck deck = this.deckRepositoryPort.save(Deck.create(
                createDeckDTO.name(),
                createDeckDTO.description(),
                userInSession
        ));

        LOGGER.debug(
                "Deck created successfully. deckId={}, userId={}",
                deck.getUuid(),
                userInSession.getUuid()
        );
        return deck;
    }
}
