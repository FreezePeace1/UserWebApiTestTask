using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record UpdateUserPasswordDto
(
    [Required(ErrorMessage = "Требуется ввести пароль")]
    string NewPassword,
    [Required(ErrorMessage = "Введите старый пароль")]
    string? OldPassword,
    Guid? UserId
);