using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record ReadUserByLoginDto
(
    [Required(ErrorMessage = "Требуется ввести логин")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string Login
);