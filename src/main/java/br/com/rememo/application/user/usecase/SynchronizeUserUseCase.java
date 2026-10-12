package br.com.rememo.application.user.usecase;

import br.com.rememo.domain.user.User;
import br.com.rememo.application.user.transport.UserInSessionDTO;

public interface SynchronizeUserUseCase {

    User synchronizeUser(UserInSessionDTO userInSessionDTO);
}
