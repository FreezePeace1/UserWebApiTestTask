using System.ComponentModel.DataAnnotations;
using UserWebApi.Domain.Enums;

namespace UserWebApi.Domain.Dtos;

public sealed record UserRegisterDto
(
    [Required(ErrorMessage = "Требуется ввести логин")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string Login,
    [Required(ErrorMessage = "Требуется ввести пароль")]
    [RegularExpression("^[a-zA-Z0-9]+$"
        ,ErrorMessage = "Запрещены все символы кроме латинских" +
                        "букв и цифр")]
    string Password,
    [Required(ErrorMessage = "Требуется ввести имя")]
    [RegularExpression("^[a-zA-Zа-яА-Я]+$")]
    string Name,
    [Required(ErrorMessage = "Требуется ввести пол"),Range(0,2)]
    Genders Gender,
    [Required(ErrorMessage = "Требуется ввести дату рождения")]
    DateTime Birthday,
    bool Admin = false
);