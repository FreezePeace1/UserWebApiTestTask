using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Dtos;

public sealed record UpdateUserPersonalDataDto
(
    [RegularExpression("^[a-zA-Zа-яА-Я]+$")]
    string? Name,
    [Range(0,2)]
    int? Gender,
    DateTime? Birthday,
    Guid? UserId
);