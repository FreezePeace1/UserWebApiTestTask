namespace UserWebApi.Domain.Models;

public sealed class CreateUserModel
{
    public Guid Id { get; set; }
    public string Login { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    public int Gender { get; set; }
    public DateTime? Birthday { get; set; }
    public bool Admin { get; set; }
    public List<string> Roles { get; set; } = new();
}