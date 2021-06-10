# Example C# Cryptographic Verification

This is an example of how to verify cryptographic license keys in C# and .NET.

This example verifies the `RSA_2048_PKCS1_PSS_SIGN_V2` scheme.

## Running the example

First, install dependencies with [`dotnet`](https://docs.microsoft.com/en-us/dotnet/core/tools/dotnet):

```
dotnet restore
```

Then run the program:

```
dotnet run
```

You should see log output indicating the current license key is valid:

```
[INFO] License key is cryptographically valid: key=key/... dataset=...
```

## Questions?

Reach out at [support@keygen.sh](mailto:support@keygen.sh) if you have any
questions or concerns!
