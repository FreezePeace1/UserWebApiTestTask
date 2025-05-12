using System.ComponentModel.DataAnnotations;
using UserWebApi.Domain.Enums;

namespace UserWebApi.Domain.Dtos;

public sealed record UserRegisterDto
(
    [Required(ErrorMessage = "Требуется ввести логин")]
    string Login,
    [Required(ErrorMessage = "Требуется ввести пароль")]
    string Password,
    [Required(ErrorMessage = "Требуется ввести имя")]
    string Name,
    [Required(ErrorMessage = "Требуется ввести пол"),Range(0,2)]
    Genders Gender,
    [Required(ErrorMessage = "Требуется ввести дату рождения")]
    DateTime Birthday,
    bool Admin = false
);