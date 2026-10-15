package br.com.rememo.controller.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record CreateDeckRequest(@NotBlank
                                @Size(min = 3, max = 255)
                                String name,

                                @Size(max = 500)
                                String description,

                                @Size(max = 60)
                                String icon) {
}
