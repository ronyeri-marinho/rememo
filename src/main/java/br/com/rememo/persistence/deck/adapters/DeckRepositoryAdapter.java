package br.com.rememo.persistence.deck.adapters;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationResult;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.user.exception.UserNotFoundException;
import br.com.rememo.persistence.deck.DeckEntity;
import br.com.rememo.persistence.deck.DeckRepository;
import br.com.rememo.persistence.deck.mappers.DeckPersistenceMapper;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import br.com.rememo.persistence.deck.specification.DeckSpecificationBuilder;
import br.com.rememo.persistence.pagination.mappers.PaginationPersistenceMapper;
import br.com.rememo.persistence.user.UserEntity;
import br.com.rememo.persistence.user.UserRepository;
import org.springframework.data.domain.Page;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Component;

import java.util.Optional;
import java.util.UUID;

@Component
public class DeckRepositoryAdapter implements DeckRepositoryPort {

    private final UserRepository userRepository;
    private final DeckRepository deckRepository;

    public DeckRepositoryAdapter(UserRepository userRepository,
                                 DeckRepository deckRepository) {
        this.userRepository = userRepository;
        this.deckRepository = deckRepository;
    }

    @Override
    public Optional<Deck> findByUuidAndUserId(UUID uuid, Long userId) {
        return this.deckRepository.findByUuidAndUserId(uuid, userId)
                .map(DeckPersistenceMapper::toDomain);
    }

    @Override
    public PaginationResult<Deck> findAll(UUID userId, PaginationQuery paginationQuery) {
        Specification<DeckEntity> specifications = DeckSpecificationBuilder.withUser(userId);

        if (paginationQuery.hasParams()) {
            specifications = specifications.and(DeckSpecificationBuilder
                    .withParams(paginationQuery.searchParams()));
        }

        Page<DeckEntity> result = this.deckRepository.findAll(
                specifications,
                PaginationPersistenceMapper.toPageRequest(paginationQuery)
        );

        return new PaginationResult<>(
                result.getContent().stream().map(DeckPersistenceMapper::toDomain).toList(),
                result.getNumber(),
                result.getSize(),
                result.getTotalPages(),
                result.getTotalElements()
        );
    }

    @Override
    public Deck save(Deck deck) {
        UserEntity user = this.userRepository.findByUuid(deck.getUser().getUuid())
                .orElseThrow(() -> new UserNotFoundException("User is not found: " + deck.getUser().getUuid()));

        return DeckPersistenceMapper
                .toDomain(this.deckRepository.save(DeckPersistenceMapper.toEntity(deck, user)));
    }
}
