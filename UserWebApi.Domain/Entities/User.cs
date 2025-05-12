using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Entities;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    [RegularExpression("^[a-zA-Z0-9]+$")]
    public string Login { get; set; } = string.Empty;
    [RegularExpression("^[a-zA-Z0-9]+$")]
    public string Password { get; set; } = string.Empty;
    [RegularExpression("^[a-zA-Zа-яА-Я]+$")]
    public string Name { get; set; } = string.Empty;
    [Range(0,2)]
    public int Gender { get; set; }
    public DateTime? Birthday { get; set; }
    public bool Admin { get; set; } = false;
    public DateTime CreatedOn { get; set; } = DateTime.UtcNow;
    public string CreatedBy { get; set; } = string.Empty;
    public DateTime? ModifiedOn { get; set; }
    public DateTime? RevokedOn { get; set; }
    public string RevokedBy { get; set; } = string.Empty;
    public List<Role> Roles { get; set; } = new();
}