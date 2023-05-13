package ru.golovin.webfluxserver.mapper;

import org.mapstruct.InheritInverseConfiguration;
import org.mapstruct.Mapper;
import ru.golovin.webfluxserver.dto.UserDto;
import ru.golovin.webfluxserver.entity.User;

@Mapper(componentModel = "spring")
public interface UserMapper {

    UserDto map(User user);

    @InheritInverseConfiguration
    User map(UserDto dto);
}
