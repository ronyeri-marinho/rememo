package br.com.rememo.application.pagination;

public record PaginationSort(PaginationSortDirectionEnum direction,
                             String property) {
}
