package br.com.rememo.persistence.deck.adapters;

import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.user.exception.UserNotFoundException;
import br.com.rememo.persistence.deck.DeckRepository;
import br.com.rememo.persistence.deck.mappers.DeckPersistenceMapper;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import br.com.rememo.persistence.user.UserEntity;
import br.com.rememo.persistence.user.UserRepository;
import org.springframework.stereotype.Component;

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
    public Deck save(Deck deck) {
        UserEntity user = this.userRepository.findByUuid(deck.getUser().getUuid())
                .orElseThrow(() -> new UserNotFoundException("User is not found: " + deck.getUser().getUuid()));

        return DeckPersistenceMapper
                .toDomain(this.deckRepository.save(DeckPersistenceMapper.toEntity(deck, user)));
    }
}
