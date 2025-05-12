using Microsoft.Extensions.DependencyInjection;
using UserWebApi.Application.Services;
using UserWebApi.Application.Services.Data;
using UserWebApi.Application.Services.Interfaces;

namespace UserWebApi.Application.DependencyInjection;

public static class DependencyInjection
{
    public static IServiceCollection AddServices(this IServiceCollection services)
    {
        services.AddScoped<IUserService, UserService>();
        services.AddTransient<Initializer>();
        
        return services;
    }
}