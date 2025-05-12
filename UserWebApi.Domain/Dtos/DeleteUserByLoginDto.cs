using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record DeleteUserByLoginDto
(
    [Required(ErrorMessage = "Введите логин")]
    string Login,
    bool IsSoftDeleting = false
);