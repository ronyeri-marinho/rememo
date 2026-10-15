package br.com.rememo.controller.mappers;

import br.com.rememo.application.pagination.PaginationQuery;
import br.com.rememo.application.pagination.PaginationSort;
import br.com.rememo.application.pagination.PaginationSortDirectionEnum;
import br.com.rememo.application.pagination.SearchParam;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;

import java.util.List;

public class PaginationRestMapper {

    private PaginationRestMapper() {

    }

    public static PaginationQuery toPaginationQuery(Pageable pageable, List<SearchParam> searchParams) {
        return new PaginationQuery(
                pageable.getPageNumber(),
                pageable.getPageSize(),
                searchParams,
                pageable.getSort().stream().map(PaginationRestMapper::toPaginationSort).toList()
        );
    }

    public static PaginationSort toPaginationSort(Sort.Order order) {
        return new PaginationSort(
                PaginationSortDirectionEnum.fromString(order.getDirection().toString()),
                order.getProperty()
        );
    }
}
