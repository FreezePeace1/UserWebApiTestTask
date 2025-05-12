using Microsoft.EntityFrameworkCore;
using UserWebApi.Domain.Entities;

namespace UserWebApi.DAL.Context;

public class UserWebApiContext : DbContext
{
    public UserWebApiContext(DbContextOptions<UserWebApiContext> opts) : base(opts)
    {
        /*Database.EnsureCreated();*/
    }

    public DbSet<User> Users { get; set; }
    public DbSet<Role> Roles { get; set; }
}