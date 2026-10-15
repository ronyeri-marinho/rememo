package br.com.rememo.persistence.pagination.mappers;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationSort;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;

public class PaginationPersistenceMapper {

    private PaginationPersistenceMapper() {

    }

    public static PageRequest toPageRequest(PaginationQuery paginationQuery) {
        return PageRequest.of(
                paginationQuery.page(),
                paginationQuery.size(),
                Sort.by(
                        Sort.Direction.ASC,
                        paginationQuery.sort()
                                .stream()
                                .map(PaginationSort::property)
                                .toList()
                                .toArray(new String[0])
                )
        );
    }
}
