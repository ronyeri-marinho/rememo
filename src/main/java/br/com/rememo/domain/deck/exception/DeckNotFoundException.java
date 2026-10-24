package br.com.rememo.domain.deck.exception;

import br.com.rememo.domain.common.exception.NotFoundException;

public class DeckNotFoundException extends NotFoundException {
    
    public DeckNotFoundException(String message) {
        super(message);
    }
}
