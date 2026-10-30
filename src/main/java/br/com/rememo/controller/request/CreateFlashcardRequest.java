package br.com.rememo.controller.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateFlashcardRequest(@NotBlank
                                     @Size(min = 3, max = 500)
                                     String question,

                                     @NotBlank
                                     @Size(min = 1)
                                     String answer) {
}
