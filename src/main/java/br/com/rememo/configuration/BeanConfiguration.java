package br.com.rememo.configuration;

import org.owasp.html.HtmlPolicyBuilder;
import org.owasp.html.PolicyFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class BeanConfiguration {

    @Bean
    public PolicyFactory flashcardHtmlPolicy() {
        return new HtmlPolicyBuilder()
                .allowElements(
                        "p", "br",
                        "strong", "b",
                        "em", "i",
                        "u", "s",
                        "sub", "sup",
                        "span"
                )
                .allowElements(
                        "h1", "h2", "h3",
                        "ol", "ul", "li",
                        "blockquote", "pre", "code"
                )
                .allowElements("a")
                .allowUrlProtocols("https", "http", "mailto")
                .allowAttributes("href").onElements("a")
                .requireRelNofollowOnLinks()
                .allowStyling()
                .allowAttributes("class")
                .matching(
                        java.util.regex.Pattern.compile(
                                "ql-align-(center|right|justify)"
                        )
                )
                .onElements("p", "h1", "h2", "h3", "blockquote")
                .allowWithoutAttributes("span", "a")
                .toFactory();
    }
}