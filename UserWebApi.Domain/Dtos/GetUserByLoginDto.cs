using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record GetUserByLoginDto(
    [Required(ErrorMessage = "Нужно ввести логин")] 
    string Login);
