package br.com.rememo.application.pagination;

import java.util.Arrays;

/**
 * Defines the comparison operations supported by the search mechanism
 * and their corresponding symbols in the search expression.
 *
 * <p>Each operation maps a textual symbol received in the request
 * parameter to a semantic operation that can be translated into a
 * JPA {@code Specification}, {@code CriteriaBuilder} predicate, or
 * another query mechanism.
 *
 * <ul>
 *     <li>{@link #EQUALS}: {@code =}, exact equality;</li>
 *     <li>{@link #LIKE}: {@code :}, pattern matching;</li>
 *     <li>{@link #GREATER_THAN}: {@code >}, greater-than comparison;</li>
 *     <li>{@link #GREATER_THAN_OR_EQUALS}: {@code >=}, greater-than
 *         or equal comparison;</li>
 *     <li>{@link #LESS_THAN}: {@code <}, less-than comparison;</li>
 *     <li>{@link #LESS_THAN_OR_EQUALS}: {@code <=}, less-than or
 *         equal comparison.</li>
 * </ul>
 *
 * <p>The actual behavior of each operation, including the treatment
 * of LIKE patterns and the conversion of values to the field's Java
 * type, must be implemented by the query processing layer.
 */

public enum SearchParamOperationEnum {
    EQUALS("="),
    LIKE(":"),
    GREATER_THAN(">"),
    GREATER_THAN_OR_EQUALS(">="),
    LESS_THAN("<"),
    LESS_THAN_OR_EQUALS("<=");

    private final String symbol;

    SearchParamOperationEnum(String symbol) {
        this.symbol = symbol;
    }

    public static SearchParamOperationEnum fromSymbol(String symbol) {
        return Arrays.stream(values())
                .filter(operation -> operation.symbol.equals(symbol))
                .findFirst()
                .orElseThrow(() ->
                        new IllegalArgumentException(
                                "Unsupported operation: " + symbol
                        )
                );
    }

    public String getSymbol() {
        return symbol;
    }
}
