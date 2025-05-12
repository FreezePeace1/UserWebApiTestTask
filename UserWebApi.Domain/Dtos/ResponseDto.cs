namespace UserWebApi.Domain.Dtos;

public class ResponseDto
{
    public string ErrorMessage { get; set; } = string.Empty;
    public string SuccessMessage { get; set; } = string.Empty;
    public int ErrorCode { get; set; }
    public bool IsSuccess => ErrorMessage == string.Empty;
}

public sealed class ResponseDto<T> : ResponseDto where T : class
{
    public ResponseDto() { }
    public ResponseDto(string errorMessage, string successMessage, int errorCode)
    {
        errorMessage = errorMessage;
        successMessage = successMessage;
        errorCode = errorCode;
    }
    
    public T Data { get; set; }
}

public class ResponseDto<T1,T2> : ResponseDto where T1 : class where T2 : class
{
    public ResponseDto(string errorMessage, string successMessage, int errorCode)
    {
        errorMessage = errorMessage;
        successMessage = successMessage;
        errorCode = errorCode;
    }
    
    public T1? T1Data { get; set; }
    public T2? T2Data { get; set; }
}