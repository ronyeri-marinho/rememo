package br.com.rememo.controller;

import br.com.rememo.application.deck.usecase.CreateDeckUseCase;
import br.com.rememo.application.deck.usecase.GetDeckUseCase;
import br.com.rememo.application.deck.usecase.ListDecksUseCase;
import br.com.rememo.application.pagination.PaginationResult;
import br.com.rememo.application.pagination.SearchParam;
import br.com.rememo.controller.mappers.DeckRestMapper;
import br.com.rememo.controller.mappers.PaginationRestMapper;
import br.com.rememo.controller.request.CreateDeckRequest;
import br.com.rememo.controller.response.DeckDetailsResponse;
import br.com.rememo.domain.deck.Deck;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.data.web.PageableDefault;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.List;
import java.util.UUID;

@RestController
@RequestMapping("/decks")
public class DeckController {

    private final GetDeckUseCase getDeckUseCase;
    private final ListDecksUseCase listDecksUseCase;
    private final CreateDeckUseCase createDeckUseCase;

    public DeckController(GetDeckUseCase getDeckUseCase,
                          ListDecksUseCase listDecksUseCase,
                          CreateDeckUseCase createDeckUseCase) {
        this.getDeckUseCase = getDeckUseCase;
        this.listDecksUseCase = listDecksUseCase;
        this.createDeckUseCase = createDeckUseCase;
    }

    @GetMapping("/{uuid}")
    public ResponseEntity<DeckDetailsResponse> getDeckByUuid(@PathVariable String uuid) {
        DeckDetailsResponse response = DeckRestMapper
                .toDetails(this.getDeckUseCase.getDeckByUuid(UUID.fromString(uuid)));

        return ResponseEntity.ok(response);
    }

    @GetMapping
    public ResponseEntity<Page<DeckDetailsResponse>> listDecksAsPage(@RequestParam(value = "search", required = false) List<SearchParam> searchParams,
                                                                     @PageableDefault(size = 12, sort = {"updatedAt"}, direction = Sort.Direction.DESC) Pageable pageable) {
        PaginationResult<Deck> response = this.listDecksUseCase
                .list(PaginationRestMapper.toPaginationQuery(pageable, searchParams));

        return ResponseEntity.ok(new PageImpl<>(
                response.items().stream().map(DeckRestMapper::toDetails).toList(),
                pageable,
                response.totalElements()
        ));
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
