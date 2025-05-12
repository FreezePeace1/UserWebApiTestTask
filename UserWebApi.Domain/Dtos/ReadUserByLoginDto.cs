using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record ReadUserByLoginDto
(
    [Required(ErrorMessage = "Требуется ввести логин")]
    string Login
);