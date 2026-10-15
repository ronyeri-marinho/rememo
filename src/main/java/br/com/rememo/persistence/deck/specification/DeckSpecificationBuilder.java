package br.com.rememo.persistence.deck.specification;

import br.com.rememo.application.pagination.SearchParam;
import br.com.rememo.persistence.common.SpecificationOperationResolver;
import br.com.rememo.persistence.deck.DeckEntity;
import org.springframework.data.jpa.domain.Specification;

import java.util.List;
import java.util.UUID;

public class DeckSpecificationBuilder {

    public static Specification<DeckEntity> withUser(UUID uuid) {
        return (root, criteriaQuery, criteriaBuilder) ->
                criteriaBuilder.equal(root.get("user").get("uuid"), uuid);
    }

    public static Specification<DeckEntity> withParams(List<SearchParam> searchParams) {
        if (searchParams == null || searchParams.isEmpty()) {
            return null;
        }

        return searchParams
                .stream()
                .map(DeckSpecificationBuilder::withParam)
                .reduce(Specification::and)
                .orElse(null);
    }

    private static Specification<DeckEntity> withParam(SearchParam searchParam) {
        return switch (searchParam.key()) {
            case "name" -> DeckSpecificationBuilder.name(searchParam);
            case "description" -> DeckSpecificationBuilder.description(searchParam);
            case "deckContains" -> DeckSpecificationBuilder.nameOrDescriptionContains(searchParam.value());
            default -> throw new IllegalArgumentException("There is no valid parameter for transactions filter");
        };
    }

    private static Specification<DeckEntity> name(SearchParam searchParam) {
        return SpecificationOperationResolver.asString(
                "name",
                searchParam.value(),
                searchParam.operation()
        );
    }

    private static Specification<DeckEntity> description(SearchParam searchParam) {
        return SpecificationOperationResolver.asString(
                "description",
                searchParam.value(),
                searchParam.operation()
        );
    }

    private static Specification<DeckEntity> nameOrDescriptionContains(String term) {
        return (root, query, cb) -> {
            String pattern = "%" + term.toLowerCase() + "%";

            return cb.or(
                    cb.like(cb.lower(root.get("name")), pattern),
                    cb.like(cb.lower(root.get("description")), pattern)
            );
        };
    }
}
