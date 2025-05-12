using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Serilog;
using UserWebApi.Application.Services.Interfaces;
using UserWebApi.DAL.Context;
using UserWebApi.Domain.Entities;
using UserWebApi.Domain.Enums;
using UserWebApi.Domain.Models;

namespace UserWebApi.Application.Services.Data;

public class Initializer
{
    private readonly IConfiguration _configuration;
    private readonly UserWebApiContext _dbContext;
    private readonly ILogger _logger;
    private readonly IUserService _userService;

    public Initializer(IConfiguration configuration, UserWebApiContext dbContext, ILogger logger,
        IUserService userService)
    {
        _configuration = configuration;
        _dbContext = dbContext;
        _logger = logger;
        _userService = userService;
    }

    public void Initialize()
    {
        InitializeAsync().Wait();
    }

    private async Task InitializeAsync()
    {
        await GenerateIdentity().ConfigureAwait(false);
    }

    private async Task GenerateIdentity(CancellationToken cancellationToken = default)
    {
        try
        {
            if (!await _dbContext.Roles.AnyAsync(x => x.Name == Roles.Admin, cancellationToken: cancellationToken))
            {
                await _dbContext.Roles.AddAsync(new Role()
                {
                    Name = Roles.Admin, Id = Guid.NewGuid()
                });
            }

            if (!await _dbContext.Roles.AnyAsync(x => x.Name == Roles.User, cancellationToken: cancellationToken))
            {
                await _dbContext.Roles.AddAsync(new Role()
                {
                    Name = Roles.User, Id = Guid.NewGuid()
                });
            }

            await _dbContext.SaveChangesAsync(cancellationToken);

            var adminName = _configuration["AdminInfo:Name"];
            var adminPassword = _configuration["AdminInfo:Password"];

            var accessToken = string.Empty;
            if (!await _dbContext.Users.AnyAsync(x => x.Name == adminName || x.Admin == true))
            {
                var admin = new User()
                {
                    Name = adminName,
                    Password = BCrypt.Net.BCrypt.HashPassword(adminPassword),
                    Admin = true,
                    Birthday = DateTime.UtcNow,
                    CreatedBy = adminName,
                    Login = adminName,
                    CreatedOn = DateTime.UtcNow,
                    Gender = (int)Genders.Unknown,
                    Id = Guid.NewGuid()
                };

                var adminRole = await _dbContext.Roles.FirstOrDefaultAsync(x => x.Name == Roles.Admin);

                if (adminRole is not null)
                {
                    admin.Roles.Add(adminRole);
                }

                await _dbContext.Users.AddAsync(admin, cancellationToken);
                await _dbContext.SaveChangesAsync(cancellationToken);

                accessToken = await _userService.GenerateAccessTokenForInitializer(admin,cancellationToken);
            }

            var existedAdmin = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == adminName);

            if (existedAdmin is not null)
            {
                accessToken = await _userService.GenerateAccessTokenForInitializer(existedAdmin,cancellationToken);
            }

            //Чтобы можно было удобно брать accessToken
            Console.WriteLine($"Access token Админа: {accessToken}");
        }
        catch (Exception e)
        {
            _logger.Error(e.Message);

            throw new InvalidOperationException("Ошибка при создании Админа");
        }
    }
}