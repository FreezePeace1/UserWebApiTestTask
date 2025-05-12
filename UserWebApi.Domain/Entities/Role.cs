namespace UserWebApi.Domain.Entities;

public sealed class Role
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    
    public List<User> Users { get; set; } = new();
}