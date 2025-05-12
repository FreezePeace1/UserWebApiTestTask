using UserWebApi.Domain.Dtos;
using UserWebApi.Domain.Entities;
using UserWebApi.Domain.Models;

namespace UserWebApi.Application.Services.Interfaces;

public interface IUserService
{
    Task<ResponseDto<CreateUserModel>> CreateUserAsync(UserRegisterDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto> UpdateUserPersonalDataAsync(UpdateUserPersonalDataDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto> UpdateUserPasswordAsync(UpdateUserPasswordDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto> UpdateUserLoginAsync(UpdateUserLoginDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto<IReadOnlyList<GetAllActiveUsersModel>>> GetAllActiveUsersAsync(CancellationToken cancellationToken = default);
    Task<ResponseDto<GetUserByLoginForAdminModel>> GetUserPersonalDataByLoginAsync(ReadUserByLoginDto dto);
    Task<ResponseDto<GetUserByLoginAndPasswordModel>> GetUserByLoginAndPasswordAsync(ReadUserByLoginAndPasswordDto dto);
    Task<ResponseDto<IReadOnlyList<GetAllUsersByDefiniteAgeModel>>> GetAllUsersByDefiniteAgeAsync(ReadAllUsersByDefiniteAgeDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto> DeleteUserByLoginAsync(DeleteUserByLoginDto dto,CancellationToken cancellationToken = default);
    Task<ResponseDto> RecoverUserByLoginAsync(RecoverUserByLoginDto dto,CancellationToken cancellationToken = default);
    Task<string> GenerateAccessTokenForInitializer(User user,CancellationToken cancellationToken = default);
}