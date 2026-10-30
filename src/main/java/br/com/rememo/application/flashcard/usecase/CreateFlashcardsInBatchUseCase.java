package br.com.rememo.application.flashcard.usecase;

import br.com.rememo.application.flashcard.transport.CreateFlashcardsInBatchDTO;
import br.com.rememo.domain.flashcard.Flashcard;

import java.util.List;

public interface CreateFlashcardsInBatchUseCase {

    List<Flashcard> createInBatch(CreateFlashcardsInBatchDTO createFlashcardsInBatchDTO);
}
