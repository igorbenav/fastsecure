# FastSecure

FastSecure is a flexible authentication system for FastAPI applications that supports multiple authentication methods and allows them to be used individually or in combination.

## Features

- 🔐 Multiple authentication methods:
  - JWT tokens (with refresh token support)
  - Session-based authentication
  - OAuth providers (Google, GitHub, etc.)
- 🔄 Combine multiple authentication methods
  - Require all methods (AND logic)
  - Allow alternative methods (OR logic)
  - Optional authentication methods
- 🛠️ Easy to extend with new providers
- 🔌 Pluggable architecture
- 🚀 FastAPI integration with middleware and dependencies
- ✨ Type hints and modern Python features

## Installation

```bash
pip install fastverify
```

## Quick Start

Here's a simple example using JWT authentication:

```python
from fastapi import FastAPI, Depends
from fastverify import (
    AuthenticationManager,
    JWTAuthenticationProvider,
    requires_auth
)

app = FastAPI()

# Setup authentication
auth_manager = AuthenticationManager()
jwt_auth = JWTAuthenticationProvider(
    secret_key="your-secret-key",
    access_token_expire_minutes=30
)
auth_manager.register_provider("jwt", jwt_auth)
auth_manager.add_requirement("/protected", ["jwt"])

# Protected route
@app.get("/protected")
async def protected_route(auth = Depends(requires_auth("/protected"))):
    return {"message": "Access granted", "user_id": auth.user_id}
```

## Multiple Authentication Methods

You can combine multiple authentication methods:

```python
from fastverify import (
    AuthenticationManager,
    AuthStrategy,
    JWTAuthenticationProvider,
    SessionAuthenticationProvider
)

# Setup providers
auth_manager = AuthenticationManager()
jwt_auth = JWTAuthenticationProvider(secret_key="your-secret-key")
session_auth = SessionAuthenticationProvider()

# Register providers
auth_manager.register_provider("jwt", jwt_auth)
auth_manager.register_provider("session", session_auth)

# Require both JWT and session authentication
auth_manager.add_requirement(
    "/very-secure",
    providers=["jwt", "session"],
    strategy=AuthStrategy.ALL
)

# Allow either JWT or session authentication
auth_manager.add_requirement(
    "/flexible-auth",
    providers=["jwt", "session"],
    strategy=AuthStrategy.ANY
)
```

## OAuth Integration

Adding OAuth providers is straightforward:

```python
from fastverify import GoogleAuthProvider

google_auth = GoogleAuthProvider(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="http://localhost:8000/auth/google/callback"
)
auth_manager.register_provider("google", google_auth)
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.