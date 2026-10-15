package br.com.rememo.application.deck;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationResult;
import br.com.rememo.application.deck.usecase.ListDecksUseCase;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ListDecksService implements ListDecksUseCase {
    private final GetUserInSessionUseCase getUserInSessionUseCase;
    private final DeckRepositoryPort deckRepositoryPort;

    public ListDecksService(GetUserInSessionUseCase getUserInSessionUseCase,
                            DeckRepositoryPort deckRepositoryPort) {
        this.getUserInSessionUseCase = getUserInSessionUseCase;
        this.deckRepositoryPort = deckRepositoryPort;
    }


    @Override
    @Transactional(readOnly = true)
    public PaginationResult<Deck> list(PaginationQuery paginationQuery) {
        User userInSession = this.getUserInSessionUseCase.getUserInSession();
        return this.deckRepositoryPort.findAll(userInSession.getUuid(), paginationQuery);
    }
}
