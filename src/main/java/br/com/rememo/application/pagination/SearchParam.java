package br.com.rememo.application.pagination;

public record SearchParam(String key,
                          SearchParamOperationEnum operation,
                          String value) {
}
