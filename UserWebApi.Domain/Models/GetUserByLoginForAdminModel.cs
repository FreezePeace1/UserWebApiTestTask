using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Models;

public sealed class GetUserByLoginForAdminModel
{
    public string Name { get; set; } = string.Empty;
    [Range(0, 2)] 
    public int Gender { get; set; }
    public DateTime? Birthday { get; set; }
    public DateTime? RevokedOn { get; set; }
}