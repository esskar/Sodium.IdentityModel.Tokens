# Sodium.IdentityModel.Tokens

Includes types that provide support for Sodium/NaCl SecurityTokens, Cryptographic operations: Signing, Verifying Signatures.

## Description

Helps to protect your ASP.NET core API with JSON Web Token signed using Edwards-curve 
Digital Signature Algorithm ([EdDSA][eddsa]) [curve Ed25519 digital signatures][ed25519] from the 
state-of-the-art Sodium/NaCl [Networking and Cryptography library][nacl] by [Daniel J. Bernstein][bernstein]. 

## Installation

```shell
dotnet add package Sodium.IdentityModel.Tokens
```

## Usage

### Create a key pair

First, you need to create a private/public key pair.

```csharp
using Sodium;

var keyPair = PublicKeyAuth.GenerateKeyPair();
```

You can access the private key via `keyPair.PrivateKey`. Keep it protected, it will be used to sign your tokens.
The public key will be used to verify your signed tokens. Access it via `keyPair.PublicKey`.

### Create and sign your tokens

Create a security key from the private key

```csharp
var securityKey = SodiumSecurityKey.FromPrivateKey(privateKey);
```

Create a signing credentials using the just created security key. 

```csharp
var credentials = new SigningCredentials(securityKey, SodiumAlgorithms.EdDsa)
{
    CryptoProviderFactory = new CryptoProviderFactory
    {
        CustomCryptoProvider = new SodiumCryptoProvider()
    }
};
```

Build your token based on the current identity and write it with a `JwtSecurityTokenHandler`

```powershell
var tokenHandler = new JwtSecurityTokenHandler();

var claims = new List<Claim>
{
    new Claim(ClaimTypes.Name, identity.Name)
};

var securityToken = new JwtSecurityToken(
    "me",   
    "you",
    claims,    
    expires: DateTime.UtcNow.AddDays(1),    
    signingCredentials: credentials);


var token = tokenHandler.WriteToken(securityToken);
```

[eddsa]: https://en.wikipedia.org/wiki/EdDSA
[ed25519]: http://ed25519.cr.yp.to/
[nacl]: http://nacl.cr.yp.to/
[bernstein]: https://en.wikipedia.org/wiki/Daniel_J._Bernstein
