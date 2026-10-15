package br.com.rememo.persistence.common;

import br.com.rememo.application.pagination.SearchParamOperationEnum;
import org.springframework.data.jpa.domain.Specification;

import java.time.LocalDate;

public class SpecificationOperationResolver {
    protected SpecificationOperationResolver() {

    }

    public static <T> Specification<T> asString(String attribute, String value, SearchParamOperationEnum operation) {
        return switch (operation) {
            case LIKE -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .like(criteriaBuilder.lower(root.get(attribute)), "%" + value.toLowerCase() + "%");

            default -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .equal(root.get(attribute), value);
        };
    }

    public static <T> Specification<T> asLocalDate(String attribute, LocalDate value, SearchParamOperationEnum operation) {
        return switch (operation) {
            case GREATER_THAN -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .greaterThan(root.get(attribute), value);

            case GREATER_THAN_OR_EQUALS -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .greaterThanOrEqualTo(root.get(attribute), value);

            case LESS_THAN -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .lessThan(root.get(attribute), value);

            case LESS_THAN_OR_EQUALS -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .lessThanOrEqualTo(root.get(attribute), value);

            default -> (root, criteriaQuery, criteriaBuilder) -> criteriaBuilder
                    .equal(root.get(attribute), value);
        };
    }
}
