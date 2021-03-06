# Example C# Cryptographic Verification

This is an example of how to verify cryptographic license keys in C# and .NET.

This example verifies the `RSA_2048_PKCS1_PSS_SIGN_V2` scheme.

For an example of verifying `RSA_2048_PKCS1_SIGN_V2` using `System.Security.Cryptography`, see [this gist](https://gist.github.com/ezekg/567756b8658f8a2e16a61604484ea608).

For an example of verifying an `ED25519_SIGN` key, please see [this gist](https://gist.github.com/ezekg/e96ef9c71a8f97b9ffcb487b73bfe248).

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
