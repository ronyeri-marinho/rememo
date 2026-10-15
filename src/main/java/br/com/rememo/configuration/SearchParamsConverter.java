package br.com.rememo.configuration;

import br.com.rememo.application.pagination.SearchParam;
import br.com.rememo.application.pagination.SearchParamOperationEnum;
import org.springframework.core.convert.converter.Converter;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Converts a search expression received as a request parameter into a list
 * of {@link SearchParam} objects.
 *
 * <p>The input is expected to contain one or more search criteria, each
 * composed of a field name, an operation symbol, and a value, following
 * the format:
 *
 * <pre>
 * fieldName{operator}value
 * </pre>
 *
 * <p>Supported operators are:
 * <ul>
 *     <li>{@code =} — exact equality;</li>
 *     <li>{@code :} — pattern matching (LIKE);</li>
 *     <li>{@code >} — greater than;</li>
 *     <li>{@code >=} — greater than or equal to;</li>
 *     <li>{@code <} — less than;</li>
 *     <li>{@code <=} — less than or equal to.</li>
 * </ul>
 *
 * <p>Multiple criteria can be provided in a single expression, separated
 * by commas or semicolons. For example:
 *
 * <pre>
 * ?search=name:john,age>=18;status=ACTIVE
 * </pre>
 *
 * <p>The expression above produces three {@link SearchParam} objects:
 * <ul>
 *     <li>{@code name:john}</li>
 *     <li>{@code age>=18}</li>
 *     <li>{@code status=ACTIVE}</li>
 * </ul>
 *
 * <p>Field names may contain letters, digits, underscores, and dots.
 * Dots allow the representation of nested property paths, such as
 * {@code address.city=Recife}, provided that the query implementation
 * supports those paths.
 *
 * <p>Values extend from the operator to the next comma, semicolon, or
 * end of the input. Leading and trailing whitespace is removed from
 * each value.
 *
 * <p>This converter only parses the search expression. It does not
 * validate whether the specified fields exist, convert values to their
 * corresponding Java types, or execute database queries. Those
 * responsibilities belong to the search processing layer, which can
 * use the resulting parameters to build JPA {@code Specification}
 * predicates or {@code CriteriaBuilder} expressions.
 *
 * <p><strong>Important:</strong> the current implementation extracts
 * matching expressions using {@link Matcher#find()}. Consequently,
 * malformed or unsupported portions of the input may be ignored rather
 * than causing the entire expression to be rejected.
 *
 * @see SearchParam
 * @see SearchParamOperationEnum
 */
public class SearchParamsConverter implements Converter<String, List<SearchParam>> {

    private static final Pattern PATTERN =
            Pattern.compile("([\\w.]+)(>=|<=|=|>|<|:)([^,;]+)");

    /**
     * Parses the supplied search expression into individual search
     * parameters.
     *
     * <p>Each matched criterion is converted into a {@link SearchParam}
     * containing the field name, the corresponding operation, and the
     * trimmed value.
     *
     * @param source the search expression received from the request
     *               parameter; expected to contain criteria in the
     *               {@code fieldName{operator}value} format
     * @return a list of parsed search parameters, in the order in which
     * they appear in the input; an empty list if no criteria
     * match the expected pattern
     * @throws IllegalArgumentException if a matched operation symbol
     *                                  is not supported by {@link SearchParamOperationEnum#fromSymbol(String)}
     */
    @Override
    public List<SearchParam> convert(String source) {
        Matcher matcher = PATTERN.matcher(source);

        List<SearchParam> params = new ArrayList<>();
        while (matcher.find()) {
            params.add(new SearchParam(
                    matcher.group(1),
                    SearchParamOperationEnum.fromSymbol(matcher.group(2)),
                    matcher.group(3).trim()
            ));
        }
        return params;
    }
}
