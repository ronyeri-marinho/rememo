package br.com.rememo.controller;

import br.com.rememo.application.deck.usecase.CreateDeckUseCase;
import br.com.rememo.controller.mappers.DeckRestMapper;
import br.com.rememo.controller.request.CreateDeckRequest;
import br.com.rememo.controller.response.DeckDetailsResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

@RestController
@RequestMapping("/decks")
public class DeckController {

    private final CreateDeckUseCase createDeckUseCase;

    public DeckController(CreateDeckUseCase createDeckUseCase) {
        this.createDeckUseCase = createDeckUseCase;
    }

    @PostMapping
    public ResponseEntity<DeckDetailsResponse> create(@RequestBody @Valid CreateDeckRequest createDeckRequest,
                                                      UriComponentsBuilder uriComponentsBuilder) {
        DeckDetailsResponse response = DeckRestMapper
                .toDetails(this.createDeckUseCase.create(DeckRestMapper.toCreateDeckDTO(createDeckRequest)));

        return ResponseEntity.created(uriComponentsBuilder
                        .path("/decks/{uuid}")
                        .buildAndExpand(response.uuid())
                        .toUri())
                .body(response);
    }
}
