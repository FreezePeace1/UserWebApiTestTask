using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record UpdateUserLoginDto
(
    [Required(ErrorMessage = "Требуется ввести старый логин")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string OldLogin,
    [Required(ErrorMessage = "Требуется ввести новый логин")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string NewLogin
);