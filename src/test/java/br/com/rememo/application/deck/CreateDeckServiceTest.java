package br.com.rememo.application.deck;

import br.com.rememo.application.deck.transport.CreateDeckDTO;
import br.com.rememo.application.user.usecase.GetUserInSessionUseCase;
import br.com.rememo.domain.deck.Deck;
import br.com.rememo.domain.user.User;
import br.com.rememo.persistence.deck.ports.DeckRepositoryPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CreateDeckServiceTest {

    @Mock
    private GetUserInSessionUseCase getUserInSessionUseCase;

    @Mock
    private DeckRepositoryPort deckRepositoryPort;

    @InjectMocks
    private CreateDeckService createDeckService;

    @Test
    @DisplayName("Should create deck")
    void shouldCreateDeck() {
        User user = new User();
        user.setUuid(UUID.randomUUID());

        Deck createdDeck = new Deck();

        CreateDeckDTO createDeckDTO = this.setupCreateDeckDTO();

        when(this.getUserInSessionUseCase.getUserInSession())
                .thenReturn(user);

        when(this.deckRepositoryPort.save(any(Deck.class))).thenReturn(createdDeck);
        this.createDeckService.create(createDeckDTO);

        ArgumentCaptor<Deck> deckArgumentCaptor = ArgumentCaptor.forClass(Deck.class);
        verify(this.deckRepositoryPort).save(deckArgumentCaptor.capture());
        Deck deck = deckArgumentCaptor.getValue();

        createdDeck.setUuid(deck.getUuid());

        assertNotNull(deck);
        assertNotNull(deck.getUuid());
        assertEquals(createDeckDTO.name(), deck.getName());
        assertEquals(createDeckDTO.description(), deck.getDescription());
        assertEquals(createDeckDTO.icon(), deck.getIcon());
        assertEquals(user.getUuid(), deck.getUser().getUuid());
        assertNotNull(deck.getCreatedAt());
        assertNotNull(deck.getUpdatedAt());
    }

    private CreateDeckDTO setupCreateDeckDTO() {
        return new CreateDeckDTO(
                "My Awesome Deck",
                "This is a test for my awesome deck.",
                "study"
        );
    }
}