namespace AccessServer.Application.Common;

public readonly struct Result<T>
{
    private readonly T? _value;

    private Result(T value)
    {
        _value = value;
        Error = null;
    }

    private Result(Error error)
    {
        _value = default;
        Error = error;
    }

    public Error? Error { get; }

    public bool IsSuccess => Error is null;

    public T Value => IsSuccess
        ? _value!
        : throw new InvalidOperationException(
            $"Muvaffaqiyatsiz natijadan qiymat so'raldi: {Error!.Code}");

    public static Result<T> Success(T value) => new(value);

    public static Result<T> Failure(Error error) => new(error);

    public static implicit operator Result<T>(T value) => Success(value);

    public static implicit operator Result<T>(Error error) => Failure(error);
}

public readonly struct Result
{
    private Result(Error? error) => Error = error;

    public Error? Error { get; }

    public bool IsSuccess => Error is null;

    public static Result Success() => new(null);

    public static Result Failure(Error error) => new(error);

    public static implicit operator Result(Error error) => Failure(error);
}
