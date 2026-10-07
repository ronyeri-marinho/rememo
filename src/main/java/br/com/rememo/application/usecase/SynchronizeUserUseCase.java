package br.com.rememo.application.usecase;

import br.com.rememo.domain.User;
import br.com.rememo.application.transport.SessionUserDTO;

public interface SynchronizeUserUseCase {

    User synchronizeUser(SessionUserDTO sessionUserDTO);
}
