package br.com.rememo.controller.mappers;

import br.com.rememo.application.deck.transport.CreateDeckDTO;
import br.com.rememo.controller.request.CreateDeckRequest;
import br.com.rememo.controller.response.DeckDetailsResponse;
import br.com.rememo.domain.deck.Deck;

public class DeckRestMapper {
    private DeckRestMapper() {

    }

    public static DeckDetailsResponse toDetails(Deck deck) {
        return new DeckDetailsResponse(
                deck.getUuid().toString(),
                deck.getName(),
                deck.getDescription(),
                deck.getIcon(),
                deck.getCreatedAt(),
                deck.getUpdatedAt()
        );
    }

    public static CreateDeckDTO toCreateDeckDTO(CreateDeckRequest request) {
        return new CreateDeckDTO(
                request.name(),
                request.description(),
                request.icon()
        );
    }
}
