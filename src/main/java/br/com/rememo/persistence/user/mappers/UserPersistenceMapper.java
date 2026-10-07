package br.com.rememo.persistence.user.mappers;

import br.com.rememo.domain.User;
import br.com.rememo.persistence.user.UserEntity;

public class UserPersistenceMapper {

    private UserPersistenceMapper() {

    }

    public static User toDomain(UserEntity userEntity) {
        User user = new User();
        user.setId(userEntity.getId());
        user.setUuid(userEntity.getUuid());
        user.setIdentityProviderId(userEntity.getIdentityProviderId());
        user.setFirstName(userEntity.getFirstName());
        user.setLastName(userEntity.getLastName());
        user.setEmail(userEntity.getEmail());
        user.setCreatedAt(userEntity.getCreatedAt());
        user.setUpdatedAt(userEntity.getUpdatedAt());
        return user;
    }

    public static UserEntity toEntity(User user) {
        UserEntity userEntity = new UserEntity();
        userEntity.setId(user.getId());
        userEntity.setUuid(user.getUuid());
        userEntity.setIdentityProviderId(user.getIdentityProviderId());
        userEntity.setFirstName(user.getFirstName());
        userEntity.setLastName(user.getLastName());
        userEntity.setEmail(user.getEmail());
        userEntity.setCreatedAt(user.getCreatedAt());
        userEntity.setUpdatedAt(user.getUpdatedAt());
        return userEntity;
    }
}
