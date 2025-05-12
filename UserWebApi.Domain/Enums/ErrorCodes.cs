namespace UserWebApi.Domain.Enums;

public enum ErrorCodes
{
    FailedToCreateUser,
    UserIsNotAuthorizedOrDeleted,
    FailedToUpdateUser,
    UserAlreadyExistsWithThisLogin,
    EnterNeededDtoValues,
    FailedToFindUser,
    UserUpdatingPasswordIsFailed,
    CheckYourCurrentPassword,
    FailedToUpdateLoginOfUser,
    NotSupportedCondition,
    NoAccessRights,
    GettingActiveUsersIsFailed,
    GettingUserPersonalDataByLoginIsFailed,
    CheckYourCredentials,
    GettingUserByLoginAndPasswordIsFailed,
    GettingAllUsersByDefiniteAgeIsFailed,
    FailedToDeleteUser,
    RecoveringUserByLoginIsFailed,
    UserInCookieAndAdminCheckingIsFailed
}