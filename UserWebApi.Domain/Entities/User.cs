using System.ComponentModel.DataAnnotations;

namespace UserWebApi.Domain.Entities;

public sealed class User
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string Login { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
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