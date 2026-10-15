package br.com.rememo.application.deck.usecase;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationResult;
import br.com.rememo.domain.deck.Deck;

public interface ListDecksUseCase {

    PaginationResult<Deck> list(PaginationQuery paginationQuery);
}
