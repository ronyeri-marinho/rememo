package br.com.rememo.application.user.usecase;

import br.com.rememo.domain.user.User;
import br.com.rememo.domain.user.exception.UserNotFoundException;

public interface GetUserInSessionUseCase {

    User getUserInSession() throws UserNotFoundException;
}
