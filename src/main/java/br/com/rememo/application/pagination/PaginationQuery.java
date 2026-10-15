package br.com.rememo.application.pagination;

import java.util.List;

public record PaginationQuery(int page,
                              int size,
                              List<SearchParam> searchParams,
                              List<PaginationSort> sort) {

    public boolean hasParams() {
        return this.searchParams() != null && !this.searchParams().isEmpty();
    }
}
