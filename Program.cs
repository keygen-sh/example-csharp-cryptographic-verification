using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Security;
using System.Text;
using System;

class Program
{
  const string KEYGEN_LICENSE_KEY = "key/eyJhY2NvdW50Ijp7ImlkIjoiMWZkZGNlYzgtOGRkMy00ZDhkLTliMTYtMjE1Y2FjMGY5YjUyIn0sInByb2R1Y3QiOnsiaWQiOiI2YjViYjVhMy0wZTMyLTQyMjYtODhmZC04NmE5N2VjZDA2NzgifSwicG9saWN5Ijp7ImlkIjoiY2IyN2E1ZTQtYjAxYS00OTFkLTg5MzctNWY2MmJjOGIzMmVkIiwiZHVyYXRpb24iOm51bGx9LCJ1c2VyIjpudWxsLCJsaWNlbnNlIjp7ImlkIjoiYWRhNmUwYTgtZDIyOS00MjY4LWE3OGMtMWFkZGJiMDg2MzIwIiwiY3JlYXRlZCI6IjIwMjEtMDMtMjJUMTM6MzA6MTcuODkyWiIsImV4cGlyeSI6bnVsbH19.PtRHZAiiF3lInyMjyudoHfCRmMYnfMk82xG-_6v68LIx7EyjqW1gDeVlKOMXHb6HnV8HJJiV5yoW9Vc5UKa_l3Z_rS3qQdTloKE5hNW7mzuYkV2ReZ_6Q8QGItMZbpZkGr-GHHsVJrkQoFolFM0c9Nlz9eoxibtIK8VOsnxbOkfoZSH3uTpDqGpKBaa0jNvivCtL0211PKsXtGgCz32qnNvEGSHRs4XEZ1ZLEJ5cyyeBdSqwkkTl0nUepMd9nCSYT3b0RhpIIgv9ybJPPrwTa4fNt7MbL8aDizfrDewvNdrEN8n3vEXdg_vZ0uKZxamoLa02fdo5rTA654Q-9gEd-g==";
  const string KEYGEN_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF6UEFzZURZdXBLNzhaVWFTYkd3NwpZeVVDQ2VLby8xWHFUQUNPY21UVEhIR2dlSGFjTEsyajlVcmJUbGhXNWg4VnlvMGlVRUhyWTFLZ2Y0d3dpR2dGCmgwWWMrb0RXRGhxMWJJZXJ0STAzQUU0MjBMYnBVZjZPVGlvWCtuWTBFSW54WEYzSjdhQWR4L1IvbllnUkpyTFoKOUFUV2FRVlNnZjN2dHhDdEN3VWVLeEtaSTQxR0EvOUtIVGNDbWQzQnJ5QVExcGlZUHIrcXJFR2YyTkRKZ3IzVwp2VnJNdG5qZW9vcmRBYUNUeVlLdGZtNTZXR1hlWHI0M2RmZGVqQnVJa0k1a3FTendWeW94aG5qRS9SajZ4a3M4CmZmSCtka0FQTndtMElweFhKZXJ5YmptUFd5djdpeVhFVU44Q0tHKzY0MzBEN05vWUhwL2M5OTFaSFFCVXM1OWcKdndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==";

  public static void Main (string[] args)
  {
    var pemPublicKey = Encoding.UTF8.GetString(
      Convert.FromBase64String(KEYGEN_PUBLIC_KEY)
    );

    // Parse and convert the base64 PEM public key to ASN1 format
    var encodedAns1PublicKey = pemPublicKey
        .Replace("-----BEGIN PUBLIC KEY-----", string.Empty)
        .Replace("-----END PUBLIC KEY-----", string.Empty)
        .Trim();
    var asn1PublicKey = Convert.FromBase64String(encodedAns1PublicKey);

    // Import the public key
    var publicKey = PublicKeyFactory.CreateKey(asn1PublicKey);

    // Calculate the "max" salt length
    var keyLength = (int) Math.Ceiling((2048 - 1) / 8.0);
    var digest = new Sha256Digest();
    var saltLength = keyLength - digest.GetDigestSize() - 2;

    // Initialize RSA
    var engine = new RsaEngine();
    var pss = new PssSigner(engine, digest, saltLength);

    pss.Init(false, publicKey);

    // Parse the license key
    var licenseKey = KEYGEN_LICENSE_KEY;
    var keyParts = licenseKey.Split('.');
    var signingData = keyParts[0];
    var encodedSignature = ConvertBase64UrlString(keyParts[1]);
    var dataParts = signingData.Split('/');
    var signingPrefix = dataParts[0];
    var encodedData = ConvertBase64UrlString(dataParts[1]);

    if (signingPrefix != "key")
    {
      Console.WriteLine("[ERROR] Invalid license key prefix: prefix={0}", signingPrefix);

      Environment.Exit(1);
    }

    // Convert data to bytes for verification
    var signingDataBytes = Encoding.UTF8.GetBytes($"key/{encodedData}");
    var signatureBytes = Convert.FromBase64String(encodedSignature);

    // Verify the license key signature
    pss.BlockUpdate(signingDataBytes, 0, signingDataBytes.Length);

    var ok = pss.VerifySignature(signatureBytes);
    if (ok)
    {
      var decodedDataBytes = Convert.FromBase64String(encodedData);
      var decodedData = Encoding.UTF8.GetString(decodedDataBytes);

      Console.WriteLine("[INFO] License key is cryptographically valid: key={0} dataset={1}", licenseKey, decodedData);

      Environment.Exit(0);
    }
    else
    {
      Console.WriteLine("[ERROR] Kicense key is not valid: key={0}", licenseKey);

      Environment.Exit(1);
    }
  }

  // Cryptographic keys use base64url encoding: https://keygen.sh/docs/api/#license-signatures
  private static string ConvertBase64UrlString(string s)
  {
    return s.Replace("-", "+").Replace("_", "/");
  }
}
