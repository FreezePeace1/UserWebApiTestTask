using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using UserWebApi.Application.Services.Interfaces;
using UserWebApi.Domain.Dtos;
using UserWebApi.Domain.Entities;
using UserWebApi.Domain.Models;

namespace UserWebApi.Controllers;

[ApiController]
[Route("api/[controller]")]
public class UserController : ControllerBase
{
    private readonly IUserService _userService;

    public UserController(IUserService userService)
    {
        _userService = userService;
    }

    [HttpPost("CreateUser")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto<User>>> CreateUserAsync(UserRegisterDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.CreateUserAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }
    
    [HttpPut("UpdateUserPersonalData")]
    [Authorize]
    public async Task<ActionResult<ResponseDto>> UpdateUserPersonalDataAsync(UpdateUserPersonalDataDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.UpdateUserPersonalDataAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpPut("UpdateUserPassword")]
    [Authorize]
    public async Task<ActionResult<ResponseDto>> UpdateUserPasswordAsync(UpdateUserPasswordDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.UpdateUserPasswordAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpPut("UpdateUserLogin")]
    [Authorize]
    public async Task<ActionResult<ResponseDto>> UpdateUserLoginAsync(UpdateUserLoginDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.UpdateUserLoginAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpGet("GetAllActiveUsers")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto<IReadOnlyList<User>>>> GetAllActiveUsersAsync(CancellationToken cancellationToken)
    {
        var response = await _userService.GetAllActiveUsersAsync(cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpGet("GetUserPersonalDataByLogin")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto<GetUserByLoginForAdminModel>>> GetUserPersonalDataByLoginAsync(ReadUserByLoginDto dto)
    {
        var response = await _userService.GetUserPersonalDataByLoginAsync(dto);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpGet("GetUserByLoginAndPassword")]
    [Authorize]
    public async Task<ActionResult<ResponseDto<User>>> GetUserByLoginAndPasswordAsync(ReadUserByLoginAndPasswordDto dto)
    {
        var response = await _userService.GetUserByLoginAndPasswordAsync(dto);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpGet("GetAllUsersByDefiniteAge")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto<IReadOnlyList<User>>>> GetAllUsersByDefiniteAgeAsync(ReadAllUsersByDefiniteAgeDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.GetAllUsersByDefiniteAgeAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpDelete("DeleteUserByLogin")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto>> DeleteUserByLoginAsync(DeleteUserByLoginDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.DeleteUserByLoginAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }

    [HttpPut("RecoverUserByLogin")]
    [Authorize(Policy = "AdminOnly")]
    public async Task<ActionResult<ResponseDto>> RecoverUserByLoginAsync(RecoverUserByLoginDto dto,CancellationToken cancellationToken)
    {
        var response = await _userService.RecoverUserByLoginAsync(dto,cancellationToken);

        if (response.IsSuccess)
        {
            return Ok(response);
        }
        
        return BadRequest(response);
    }
}