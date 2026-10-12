package br.com.rememo.domain.user.exception;

import br.com.rememo.domain.common.exception.NotFoundException;

public class UserNotFoundException extends NotFoundException {

    public UserNotFoundException(String message) {
        super(message);
    }
}
