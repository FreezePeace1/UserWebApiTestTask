using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record ReadUserByLoginAndPasswordDto
(
    [Required(ErrorMessage = "Требуется ввести логин")]
    string Login,
    [Required(ErrorMessage = "Требуется ввести пароль")]
    string Password
);