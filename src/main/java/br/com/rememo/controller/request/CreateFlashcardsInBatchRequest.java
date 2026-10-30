package br.com.rememo.controller.request;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;

import java.util.List;

public record CreateFlashcardsInBatchRequest(@NotEmpty @Valid List<CreateFlashcardRequest> flashcards) {
}
