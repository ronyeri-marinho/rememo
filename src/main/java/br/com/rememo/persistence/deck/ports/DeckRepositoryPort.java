package br.com.rememo.persistence.deck.ports;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationResult;
import br.com.rememo.domain.deck.Deck;

import java.util.Optional;
import java.util.UUID;

public interface DeckRepositoryPort {

    Optional<Deck> findByUuidAndUserId(UUID uuid, Long userId);

    PaginationResult<Deck> findAll(UUID userId, PaginationQuery paginationQuery);

    Deck save(Deck deck);
}
