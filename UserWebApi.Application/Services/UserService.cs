using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using UserWebApi.Application.Services.Interfaces;
using UserWebApi.Application.Sources;
using UserWebApi.DAL.Context;
using UserWebApi.Domain.Dtos;
using UserWebApi.Domain.Entities;
using UserWebApi.Domain.Enums;
using UserWebApi.Domain.Models;

namespace UserWebApi.Application.Services;

public sealed class UserService : IUserService
{
    private readonly UserWebApiContext _dbContext;
    private readonly ILogger _logger;
    private readonly IHttpContextAccessor _httpContext;
    private readonly IConfiguration _configuration;

    public UserService(UserWebApiContext dbContext, ILogger logger, IHttpContextAccessor httpContext
        , IConfiguration configuration)
    {
        _dbContext = dbContext;
        _logger = logger;
        _httpContext = httpContext;
        _configuration = configuration;
    }

    public async Task<ResponseDto<CreateUserModel>> CreateUserAsync(UserRegisterDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует
            if (existedUser is null)
            {
                return new ResponseDto<CreateUserModel>()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            // Пользователь не админ
            if (!existedUser.Admin)
            {
                return new ResponseDto<CreateUserModel>()
                {
                    ErrorMessage = ErrorMessages.NoAccessRights,
                    ErrorCode = (int)ErrorCodes.NoAccessRights
                };
            }

            var existedUserWithLogin = await _dbContext.Users.AnyAsync(x => x.Login == dto.Login);

            if (existedUserWithLogin)
            {
                return new ResponseDto<CreateUserModel>()
                {
                    ErrorMessage = ErrorMessages.UserAlreadyExistsWithThisLogin,
                    ErrorCode = (int)ErrorCodes.UserAlreadyExistsWithThisLogin
                };
            }

            var newUser = new User()
            {
                Id = Guid.NewGuid(),
                Name = dto.Name,
                Birthday = dto.Birthday,
                CreatedOn = DateTime.UtcNow,
                Gender = (int)dto.Gender,
                Login = dto.Login,
                Password = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                Admin = dto.Admin,
                CreatedBy = existedUser.Login
            };


            newUser.Roles.Add(!dto.Admin
                ? await _dbContext.Roles.FirstOrDefaultAsync(x => x.Name == Roles.User)
                : await _dbContext.Roles.FirstOrDefaultAsync(x => x.Name == Roles.Admin));

            await _dbContext.Users.AddAsync(newUser);
            await _dbContext.SaveChangesAsync(cancellationToken);

            var accessToken = await GenerateAndSetAccessToken(newUser, cancellationToken);

            _logger.Information(SuccessMessages.UserCreationIsSucceed);

            var newModel = new CreateUserModel()
            {
                Id = newUser.Id,
                Name = newUser.Name,
                Birthday = newUser.Birthday,
                Admin = newUser.Admin,
                Gender = newUser.Gender,
                Login = newUser.Login,
                Roles = newUser.Roles.Select(x => x.Name).ToList()
            };

            return new ResponseDto<CreateUserModel>()
            {
                SuccessMessage = SuccessMessages.UserCreationIsSucceed + " " + accessToken,
                Data = newModel
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<CreateUserModel>()
            {
                ErrorMessage = ErrorMessages.FailedToCreateUser,
                ErrorCode = (int)ErrorCodes.FailedToCreateUser
            };
        }
    }

    private async Task<string> GenerateAndSetAccessToken(User user, CancellationToken cancellationToken = default)
    {
        try
        {
            var userRoles = await _dbContext.Users
                .Where(u => u.Id == user.Id)
                .SelectMany(u => u.Roles)
                .AsNoTracking()
                .ToListAsync(cancellationToken: cancellationToken);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Gender, user.Gender.ToString())
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            var accessToken = GenerateJWT(claims);
            SetAccessToken(accessToken);

            return accessToken;
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);
            
            throw;
        }
    }

    private void SetAccessToken(string accessToken)
    {
        var cookieOpts = new CookieOptions()
        {
            HttpOnly = true,
            Expires = DateTime.UtcNow.AddMinutes(CookieInfo.AccessTokenExpiresTime)
        };

        _httpContext.HttpContext.Response.Cookies.Append(CookieInfo.AccessToken, accessToken, cookieOpts);
    }

    private string GenerateJWT(List<Claim> claims)
    {
        var secret = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JwtSettings:Key"]));

        var tokenObject = new JwtSecurityToken(
            issuer: _configuration["JwtSettings:Issuer"],
            audience: _configuration["JwtSettings:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(CookieInfo.AccessTokenExpiresTime),
            signingCredentials: new SigningCredentials(secret, SecurityAlgorithms.HmacSha256)
        );

        string token = new JwtSecurityTokenHandler().WriteToken(tokenObject);

        return token;
    }

    public async Task<ResponseDto> UpdateUserPersonalDataAsync(UpdateUserPersonalDataDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не сушествует или удален
            if (existedUser is null || !string.IsNullOrEmpty(existedUser.RevokedOn.ToString()))
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            //Пользователь не является админом => меняет себя
            if (existedUser.Admin == false)
            {
                existedUser.Name = dto.Name ?? existedUser.Name;
                existedUser.Gender = dto.Gender ?? existedUser.Gender;
                existedUser.Birthday = dto.Birthday ?? existedUser.Birthday;
                existedUser.ModifiedOn = DateTime.UtcNow;

                await _dbContext.SaveChangesAsync(cancellationToken);

                _logger.Information(SuccessMessages.UserUpdatingIsSucceed + "by usual user");

                return new ResponseDto()
                {
                    SuccessMessage = SuccessMessages.UserUpdatingIsSucceed
                };
            }

            if (dto.UserId is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.EnterNeededDtoValues,
                    ErrorCode = (int)ErrorCodes.EnterNeededDtoValues
                };
            }

            if (dto.UserId is not null)
            {
                //Пользователь является админом => меняет другого пользователя, нужно найти пользователя по данным
                var requiredUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == dto.UserId);

                if (existedUser.Admin && dto.Name != existedUser.Name && requiredUser is not null)
                {
                    requiredUser.Name = dto.Name ?? requiredUser.Name;
                    requiredUser.Gender = dto.Gender ?? requiredUser.Gender;
                    requiredUser.Birthday = dto.Birthday ?? requiredUser.Birthday;
                    requiredUser.ModifiedOn = DateTime.UtcNow;

                    _logger.Information(SuccessMessages.UserUpdatingIsSucceed + "by admin user");

                    await _dbContext.SaveChangesAsync(cancellationToken);

                    return new ResponseDto()
                    {
                        SuccessMessage = SuccessMessages.UserUpdatingIsSucceed
                    };
                }
            }

            _logger.Warning(ErrorMessages.NotSupportedCondition + "не удалось обновить пользователя");

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.NotSupportedCondition
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.FailedToUpdateUser,
                ErrorCode = (int)ErrorCodes.FailedToUpdateUser
            };
        }
    }

    public async Task<ResponseDto> UpdateUserPasswordAsync(UpdateUserPasswordDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует или удален
            if (existedUser is null || !string.IsNullOrEmpty(existedUser.RevokedOn.ToString()))
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            // Если сам пользователь меняет себе пароль и должен подтвердить свой пароль введя старый
            if (existedUser.Admin == false)
            {
                if (!BCrypt.Net.BCrypt.Verify(dto.OldPassword, existedUser.Password))
                {
                    return new ResponseDto()
                    {
                        ErrorMessage = ErrorMessages.CheckYourCurrentPassword,
                        ErrorCode = (int)ErrorCodes.CheckYourCurrentPassword
                    };
                }

                existedUser.Password = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
                existedUser.ModifiedOn = DateTime.UtcNow;

                _logger.Information(SuccessMessages.UserUpdatingPasswordIsSucceed + "by user");

                await _dbContext.SaveChangesAsync(cancellationToken);

                return new ResponseDto()
                {
                    SuccessMessage = SuccessMessages.UserUpdatingPasswordIsSucceed
                };
            }

            // Если админ меняет пароль, то нужно найти пользователя и не нужно подтверждать через старый пароль
            if (dto.UserId is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.EnterNeededDtoValues,
                    ErrorCode = (int)ErrorCodes.EnterNeededDtoValues
                };
            }

            var requiredUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Id == dto.UserId);

            if (requiredUser is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.FailedToFindUser,
                    ErrorCode = (int)ErrorCodes.FailedToFindUser
                };
            }

            requiredUser.Password = BCrypt.Net.BCrypt.HashPassword(dto.NewPassword);
            requiredUser.ModifiedOn = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync(cancellationToken);

            _logger.Information(SuccessMessages.UserUpdatingPasswordIsSucceed + "by admin");

            return new ResponseDto()
            {
                SuccessMessage = SuccessMessages.UserUpdatingPasswordIsSucceed
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.UserUpdatingPasswordIsFailed,
                ErrorCode = (int)ErrorCodes.UserUpdatingPasswordIsFailed
            };
        }
    }

    public async Task<ResponseDto> UpdateUserLoginAsync(UpdateUserLoginDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            // Проверяем существует ли уже логин в бд
            var existedUserWithLogin =
                await _dbContext.Users.AnyAsync(x => x.Login == dto.NewLogin);

            if (existedUserWithLogin)
            {
                return new ResponseDto<User>()
                {
                    ErrorMessage = ErrorMessages.UserAlreadyExistsWithThisLogin,
                    ErrorCode = (int)ErrorCodes.UserAlreadyExistsWithThisLogin
                };
            }

            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует или удален
            if (existedUser is null || !string.IsNullOrEmpty(existedUser.RevokedOn.ToString()))
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            var existedUserWithOldLogin = await _dbContext.Users.FirstOrDefaultAsync(x => x.Login == dto.OldLogin);

            if (existedUserWithOldLogin is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.FailedToFindUser,
                    ErrorCode = (int)ErrorCodes.FailedToFindUser
                };
            }
            
            // Если меняет логин сам пользователь или пользователь админ
            if (dto.OldLogin == existedUserWithOldLogin.Login || existedUser.Admin)
            {
                existedUserWithOldLogin.Login = dto.NewLogin;
                existedUserWithOldLogin.ModifiedOn = DateTime.UtcNow;

                await _dbContext.SaveChangesAsync(cancellationToken);

                _logger.Information(SuccessMessages.UserUpdatingPasswordIsSucceed);

                return new ResponseDto()
                {
                    SuccessMessage = SuccessMessages.UserUpdatingPasswordIsSucceed
                };
            }

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.NotSupportedCondition,
                ErrorCode = (int)ErrorCodes.NotSupportedCondition
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.FailedToUpdateLoginOfUser,
                ErrorCode = (int)ErrorCodes.FailedToUpdateLoginOfUser
            };
        }
    }

    public async Task<ResponseDto<IReadOnlyList<GetAllActiveUsersModel>>> GetAllActiveUsersAsync(
        CancellationToken cancellationToken = default)
    {
        try
        {
            var isUserInCookieAndAdmin = await IsUserInCookieAndAdmin<IReadOnlyList<GetAllActiveUsersModel>>();

            if (!isUserInCookieAndAdmin.IsSuccess)
            {
                return isUserInCookieAndAdmin;
            }

            // Получаем список активных пользователей
            var listActiveUsers = await _dbContext.Users
                .Where(x => string.IsNullOrEmpty(x.RevokedOn.ToString()))
                .OrderBy(x => x.CreatedOn)
                .Select(x => new GetAllActiveUsersModel()
                {
                    Admin = x.Admin,
                    Birthday = x.Birthday,
                    Gender = x.Gender,
                    Id = x.Id,
                    Login = x.Login,
                    Name = x.Name,
                    Roles = x.Roles.Select(x => x.Name).ToList(),
                })
                .AsNoTracking()
                .ToListAsync(cancellationToken: cancellationToken);

            _logger.Information(SuccessMessages.GettingActiveUsersIsSucceed);

            return new ResponseDto<IReadOnlyList<GetAllActiveUsersModel>>()
            {
                Data = listActiveUsers,
                SuccessMessage = SuccessMessages.GettingActiveUsersIsSucceed
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<IReadOnlyList<GetAllActiveUsersModel>>()
            {
                ErrorMessage = ErrorMessages.GettingActiveUsersIsFailed,
                ErrorCode = (int)ErrorCodes.GettingActiveUsersIsFailed
            };
        }
    }

    private async Task<ResponseDto<T>> IsUserInCookieAndAdmin<T>() where T : class
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует
            if (existedUser is null)
            {
                return new ResponseDto<T>()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            // Пользователь не админ
            if (!existedUser.Admin)
            {
                return new ResponseDto<T>()
                {
                    ErrorMessage = ErrorMessages.NoAccessRights,
                    ErrorCode = (int)ErrorCodes.NoAccessRights
                };
            }

            return new ResponseDto<T>();
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<T>()
            {
                ErrorMessage = ErrorMessages.UserInCookieAndAdminCheckingIsFailed,
                ErrorCode = (int)ErrorCodes.UserInCookieAndAdminCheckingIsFailed
            };
        }
    }

    public async Task<ResponseDto<GetUserByLoginForAdminModel>> GetUserPersonalDataByLoginAsync(ReadUserByLoginDto dto)
    {
        try
        {
            var isUserInCookieAndAdmin = await IsUserInCookieAndAdmin<GetUserByLoginForAdminModel>();

            if (!isUserInCookieAndAdmin.IsSuccess)
            {
                return isUserInCookieAndAdmin;
            }

            // Получаем запрашиваемого пользователя по логину 
            var requestedUserByLogin = await _dbContext.Users.FirstOrDefaultAsync(x => x.Login == dto.Login);

            if (requestedUserByLogin is null)
            {
                return new ResponseDto<GetUserByLoginForAdminModel>()
                {
                    ErrorMessage = ErrorMessages.FailedToFindUser,
                    ErrorCode = (int)ErrorCodes.FailedToFindUser
                };
            }

            var newModel = new GetUserByLoginForAdminModel()
            {
                Name = requestedUserByLogin.Name,
                Birthday = requestedUserByLogin.Birthday,
                Gender = requestedUserByLogin.Gender,
                RevokedOn = requestedUserByLogin.RevokedOn
            };

            _logger.Information(SuccessMessages.GettingUserPersonalDataByLoginIsSucceed);

            return new ResponseDto<GetUserByLoginForAdminModel>()
            {
                Data = newModel,
                SuccessMessage = SuccessMessages.GettingUserPersonalDataByLoginIsSucceed
            };
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<GetUserByLoginForAdminModel>()
            {
                ErrorMessage = ErrorMessages.GettingUserPersonalDataByLoginIsFailed,
                ErrorCode = (int)ErrorCodes.GettingUserPersonalDataByLoginIsFailed
            };
        }
    }

    public async Task<ResponseDto<GetUserByLoginAndPasswordModel>> GetUserByLoginAndPasswordAsync(ReadUserByLoginAndPasswordDto dto)
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует или удален
            if (existedUser is null)
            {
                return new ResponseDto<GetUserByLoginAndPasswordModel>()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            // Проверяем правильность логина и пароля
            if (!(existedUser.Login == dto.Login && BCrypt.Net.BCrypt.Verify(dto.Password, existedUser.Password)))
            {
                return new ResponseDto<GetUserByLoginAndPasswordModel>()
                {
                    ErrorMessage = ErrorMessages.CheckYourCredentials,
                    ErrorCode = (int)ErrorCodes.CheckYourCredentials
                };
            }

            _logger.Information(SuccessMessages.GettingUserByLoginAndPasswordIsSucceed);

            var newModel = new GetUserByLoginAndPasswordModel()
            {
                Id = existedUser.Id,
                Name = existedUser.Name,
                Birthday = existedUser.Birthday,
                Admin = existedUser.Admin,
                Gender = existedUser.Gender,
                Login = existedUser.Login,
                Roles = existedUser.Roles.Select(x => x.Name).ToList()
            };
            
            return new ResponseDto<GetUserByLoginAndPasswordModel>()
            {
                Data = newModel,
                SuccessMessage = SuccessMessages.GettingUserByLoginAndPasswordIsSucceed
            };
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<GetUserByLoginAndPasswordModel>()
            {
                ErrorMessage = ErrorMessages.GettingUserByLoginAndPasswordIsFailed,
                ErrorCode = (int)ErrorCodes.GettingUserByLoginAndPasswordIsFailed
            };
        }
    }

    public async Task<ResponseDto<IReadOnlyList<GetAllUsersByDefiniteAgeModel>>> GetAllUsersByDefiniteAgeAsync(ReadAllUsersByDefiniteAgeDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var isUserInCookieAndAdmin = await IsUserInCookieAndAdmin<IReadOnlyList<GetAllUsersByDefiniteAgeModel>>();

            if (!isUserInCookieAndAdmin.IsSuccess)
            {
                return isUserInCookieAndAdmin;
            }

            // Вычисляем правильную дату
            var targetDate = DateTime.UtcNow.Date.AddYears(-dto.Age - 1);

            // Получаем нужный список
            var requestedUsersByDefiniteAge = await _dbContext.Users
                .Where(x => targetDate >= x.Birthday)
                .Select(x => new GetAllUsersByDefiniteAgeModel()
                {
                    Id = x.Id,
                    Name = x.Name,
                    Birthday = x.Birthday,
                    Admin = x.Admin,
                    Gender = x.Gender,
                    Login = x.Login,
                    Roles = x.Roles.Select(x => x.Name).ToList()
                })
                .AsNoTracking()
                .ToListAsync(cancellationToken: cancellationToken);

            _logger.Information(SuccessMessages.GettingAllUsersByDefiniteAgeIsSucceed);
            
            return new ResponseDto<IReadOnlyList<GetAllUsersByDefiniteAgeModel>>()
            {
                Data = requestedUsersByDefiniteAge,
                SuccessMessage = SuccessMessages.GettingAllUsersByDefiniteAgeIsSucceed
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto<IReadOnlyList<GetAllUsersByDefiniteAgeModel>>()
            {
                ErrorMessage = ErrorMessages.GettingAllUsersByDefiniteAgeIsFailed,
                ErrorCode = (int)ErrorCodes.GettingAllUsersByDefiniteAgeIsFailed
            };
        }
    }

    public async Task<ResponseDto> DeleteUserByLoginAsync(DeleteUserByLoginDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userName = _httpContext.HttpContext.User.Identity.Name;
            var existedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Name == userName);

            //Пользователь не существует
            if (existedUser is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.UserIsNotAuthorizedOrDeleted,
                    ErrorCode = (int)ErrorCodes.UserIsNotAuthorizedOrDeleted
                };
            }

            // Пользователь не админ
            if (!existedUser.Admin)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.NoAccessRights,
                    ErrorCode = (int)ErrorCodes.NoAccessRights
                };
            }

            var requestedUserByLogin =
                await _dbContext.Users.FirstOrDefaultAsync(x => x.Login == dto.Login);

            if (requestedUserByLogin is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.FailedToFindUser,
                    ErrorCode = (int)ErrorCodes.FailedToFindUser
                };
            }

            //если мягкое удаление
            if (dto.IsSoftDeleting)
            {
                requestedUserByLogin.RevokedBy = existedUser.Login;
                requestedUserByLogin.RevokedOn = DateTime.UtcNow;
                requestedUserByLogin.ModifiedOn = DateTime.UtcNow;

                await _dbContext.SaveChangesAsync(cancellationToken);

                _logger.Information(SuccessMessages.SoftDeletingIsSucceed);

                return new ResponseDto()
                {
                    SuccessMessage = SuccessMessages.SoftDeletingIsSucceed
                };
            }

            _dbContext.Remove(requestedUserByLogin);

            await _dbContext.SaveChangesAsync(cancellationToken);

            _logger.Information(SuccessMessages.FullDeletingIsSucceed);

            return new ResponseDto()
            {
                SuccessMessage = SuccessMessages.FullDeletingIsSucceed
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.FailedToDeleteUser,
                ErrorCode = (int)ErrorCodes.FailedToDeleteUser
            };
        }
    }

    public async Task<ResponseDto> RecoverUserByLoginAsync(RecoverUserByLoginDto dto,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var isUserInCookieAndAdmin = await IsUserInCookieAndAdmin<ResponseDto>();

            if (!isUserInCookieAndAdmin.IsSuccess)
            {
                return isUserInCookieAndAdmin;
            }

            var requestedUser = await _dbContext.Users.FirstOrDefaultAsync(x => x.Login == dto.Login);

            if (requestedUser is null)
            {
                return new ResponseDto()
                {
                    ErrorMessage = ErrorMessages.FailedToFindUser,
                    ErrorCode = (int)ErrorCodes.FailedToFindUser
                };
            }

            // Восстанавливаем пользователя
            requestedUser.RevokedOn = null;
            requestedUser.RevokedBy = string.Empty;
            requestedUser.ModifiedOn = DateTime.UtcNow;

            await _dbContext.SaveChangesAsync(cancellationToken);

            _logger.Information(SuccessMessages.RecoveringUserByLoginIsSucceed);

            return new ResponseDto()
            {
                SuccessMessage = SuccessMessages.RecoveringUserByLoginIsSucceed
            };
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            return new ResponseDto()
            {
                ErrorMessage = ErrorMessages.RecoveringUserByLoginIsFailed,
                ErrorCode = (int)ErrorCodes.RecoveringUserByLoginIsFailed
            };
        }
    }

    public async Task<string> GenerateAccessTokenForInitializer(User user,
        CancellationToken cancellationToken = default)
    {
        try
        {
            var userRoles = await _dbContext.Users
                .Where(u => u.Id == user.Id)
                .SelectMany(u => u.Roles)
                .AsNoTracking()
                .ToListAsync(cancellationToken: cancellationToken);

            var claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.Name),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim("JWTID", Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Gender, user.Gender.ToString())
            };

            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role.Name));
            }

            var accessToken = GenerateJWT(claims);

            _logger.Information("Access token was returned successfully");

            return accessToken;
        }
        catch (OperationCanceledException e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
        catch (Exception e)
        {
            _logger.Error(e, e.Message);

            throw;
        }
    }
}