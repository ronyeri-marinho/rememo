package br.com.rememo.application.common;

import br.com.rememo.application.common.usecase.HtmlSanitizerUseCase;
import org.owasp.html.PolicyFactory;
import org.springframework.stereotype.Service;

@Service
public class HtmlSanitizerService implements HtmlSanitizerUseCase {

    private final PolicyFactory policyFactory;

    public HtmlSanitizerService(PolicyFactory policyFactory) {
        this.policyFactory = policyFactory;
    }

    @Override
    public String sanitize(String html) {
        if (html == null || html.isBlank()) {
            return html;
        }

        return policyFactory.sanitize(html);
    }
}
