using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record ReadAllUsersByDefiniteAgeDto
(
    [Required(ErrorMessage = "Введите возраст")]
    int Age
);