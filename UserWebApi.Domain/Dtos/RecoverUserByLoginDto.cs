using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record RecoverUserByLoginDto
(
    [Required(ErrorMessage = "Нужно ввести логин")]
    string Login
);