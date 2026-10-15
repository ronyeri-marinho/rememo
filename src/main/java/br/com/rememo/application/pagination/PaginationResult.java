package br.com.rememo.application.pagination;

import java.util.List;

public record PaginationResult<T>(List<T> items,
                                  int page,
                                  int size,
                                  int totalPages,
                                  long totalElements) {
}