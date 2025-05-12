using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using UserWebApi.DAL.Context;

namespace UserWebApi.DAL.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddDAL(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddDbContext<UserWebApiContext>(opts =>
        {
            opts.UseNpgsql(configuration.GetConnectionString("DefaultConnection"));
        });
        
        return services;
    }
}