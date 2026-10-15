package br.com.rememo.application.pagination;

import java.util.Arrays;

public enum PaginationSortDirectionEnum {
    ASC,
    DESC;

    public static PaginationSortDirectionEnum fromString(String direction) {
        return Arrays.stream(values())
                .filter(operation -> operation.toString().equals(direction))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Unsupported operation: " + direction
                        )
                );
    }
}
