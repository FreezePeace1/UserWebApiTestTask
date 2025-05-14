using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record UpdateUserPasswordDto
(
    [Required(ErrorMessage = "Требуется ввести пароль")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string NewPassword,
    [Required(ErrorMessage = "Введите старый пароль")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string? OldPassword,
    Guid? UserId
);