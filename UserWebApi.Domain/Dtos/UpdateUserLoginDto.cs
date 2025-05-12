using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public record UpdateUserLoginDto
(
    [Required(ErrorMessage = "Требуется ввести старый логин")]
    string OldLogin,
    [Required(ErrorMessage = "Требуется ввести новый логин")]
    string NewLogin
    
);