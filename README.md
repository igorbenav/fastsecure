# FastSecure

A modern, flexible authentication system for FastAPI applications with support for multiple authentication methods and strategies.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Core Concepts](#core-concepts)
- [Basic Usage Guide](#basic-usage-guide)
  - [Setting Up JWT Authentication](#setting-up-jwt-authentication)
  - [Setting Up Session Authentication](#setting-up-session-authentication)
  - [Setting Up OAuth Authentication](#setting-up-oauth-authentication)
- [Advanced Usage Guide](#advanced-usage-guide)
  - [Combining Authentication Methods](#combining-authentication-methods)
  - [Custom Authentication Providers](#custom-authentication-providers)
  - [Storage Backends](#storage-backends)
- [Security Best Practices](#security-best-practices)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🔐 **Multiple Authentication Methods**
  - JWT tokens with refresh token support and flexible configuration
  - Session-based authentication with configurable storage backends
  - OAuth 2.0 providers (Google, GitHub) with standardized user info
  - Easy to extend with custom authentication providers

- 🔄 **Flexible Authentication Strategies**
  - Use single or multiple authentication methods
  - Support for AND logic (require all methods)
  - Support for OR logic (allow any method)
  - Optional authentication methods
  - Path-based authentication requirements

- 🗄️ **Session Storage Options**
  - In-memory storage for development
  - Redis backend for distributed systems
  - Database backend (SQLAlchemy) for persistence
  - Easy to implement custom storage backends

- 🛡️ **Security Features**
  - Token expiration and refresh
  - Session timeout and cleanup
  - Concurrent session limits
  - Scope-based authorization
  - IP tracking and user agent logging

## Installation

1. Install using pip:
```bash
pip install fastsecure
```

2. Install optional dependencies for specific features:
```bash
# Redis storage backend
pip install fastsecure[redis]

# Database storage backend
pip install fastsecure[database]

# All optional dependencies
pip install fastsecure[all]
```

## Core Concepts

Before diving into the implementation, let's understand the core concepts:

### Authentication Manager

The `AuthenticationManager` is the central component that:
- Manages authentication providers
- Handles authentication strategies
- Enforces authentication requirements
- Coordinates the authentication flow

### Authentication Providers

Providers implement specific authentication methods:
- JWT tokens
- Sessions
- OAuth
- Custom methods

### Authentication Strategies

Strategies determine how multiple authentication methods are combined:
- `AuthStrategy.ANY`: Any provider can authenticate (OR logic)
- `AuthStrategy.ALL`: All providers must authenticate (AND logic)

### Authentication Requirements

Requirements specify which authentication methods are needed for specific paths:
- Required providers
- Optional providers
- Authentication strategy
- Required scopes

## Basic Usage Guide

### Setting Up JWT Authentication

1. **Create a Basic FastAPI Application**

```python
from fastapi import FastAPI, Depends, HTTPException
from fastsecure import AuthenticationManager, JWTAuthenticationProvider

app = FastAPI()
```

2. **Initialize Authentication Manager and JWT Provider**

```python
# Initialize authentication
auth_manager = AuthenticationManager()

# Configure JWT provider
jwt_auth = JWTAuthenticationProvider(
    secret_key="your-secret-key",  # Use a secure key in production!
    access_token_expire_minutes=30,
    refresh_token_expire_days=7
)

# Register the provider
auth_manager.register_provider("jwt", jwt_auth)
```

3. **Configure Protected Routes**

```python
# Add authentication requirement for protected paths
auth_manager.add_requirement(
    "/api/protected/*",  # Path pattern
    providers=["jwt"],   # Required providers
    scopes=["read"]      # Required scopes (optional)
)
```

4. **Implement Login and Protected Routes**

```python
from pydantic import BaseModel

class LoginCredentials(BaseModel):
    username: str
    password: str

@app.post("/api/auth/login")
async def login(credentials: LoginCredentials):
    # Validate credentials (implement your own validation)
    user_id = validate_credentials(credentials)
    
    # Authenticate with JWT provider
    result = await auth_manager.authenticate(
        "/api/protected/data",
        {"jwt": {
            "user_id": user_id,
            "scopes": ["read", "write"]
        }}
    )
    
    if not result.success:
        raise HTTPException(401, "Authentication failed")
    
    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "Bearer",
        "expires_at": result.expires_at
    }

@app.get("/api/protected/data")
async def protected_data(auth = Depends(auth_manager.requires_auth)):
    return {
        "message": "Authenticated!",
        "user_id": auth.user_id,
        "scopes": auth.metadata.get("scopes", [])
    }
```

5. **Implement Token Refresh**

```python
@app.post("/api/auth/refresh")
async def refresh_token(refresh_token: str):
    result = await auth_manager.refresh_authentication(
        "jwt",
        {"refresh_token": refresh_token}
    )
    
    if not result.success:
        raise HTTPException(401, "Token refresh failed")
    
    return {
        "access_token": result.access_token,
        "refresh_token": result.refresh_token,
        "token_type": "Bearer",
        "expires_at": result.expires_at
    }
```

### Setting Up Session Authentication

1. **Choose a Storage Backend**

```python
from fastsecure import (
    SessionAuthenticationProvider,
    RedisSessionStore,
    DatabaseSessionStore
)

# For development (in-memory)
session_auth = SessionAuthenticationProvider()

# For production with Redis
session_auth = SessionAuthenticationProvider(
    session_store=RedisSessionStore("redis://localhost"),
    session_timeout_minutes=60,
    max_sessions_per_user=3,
    cleanup_expired=True
)
```

2. **Configure Session Authentication**

```python
# Register the provider
auth_manager.register_provider("session", session_auth)

# Add requirements
auth_manager.add_requirement(
    "/api/user/*",
    providers=["session"]
)
```

3. **Implement Session Login**

```python
@app.post("/api/auth/session/login")
async def session_login(
    credentials: LoginCredentials,
    request: Request
):
    user_id = validate_credentials(credentials)
    
    result = await auth_manager.authenticate(
        "/api/user/profile",
        {"session": {
            "user_id": user_id,
            "ip_address": request.client.host,
            "user_agent": request.headers.get("user-agent"),
            "scopes": ["user:read"]
        }}
    )
    
    if not result.success:
        raise HTTPException(401, "Authentication failed")
    
    response = JSONResponse({
        "message": "Logged in successfully",
        "user_id": user_id
    })
    
    # Set session cookie
    response.set_cookie(
        "session_id",
        result.session_id,
        httponly=True,
        secure=True,
        samesite="lax",
        expires=result.expires_at
    )
    
    return response
```

### Setting Up OAuth Authentication

1. **Configure OAuth Providers**

```python
from fastsecure import GoogleAuthProvider, GitHubAuthProvider

# Google Sign-In
google_auth = GoogleAuthProvider(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="http://localhost:8000/auth/google/callback"
)

# GitHub Sign-In
github_auth = GitHubAuthProvider(
    client_id="your-client-id",
    client_secret="your-client-secret",
    redirect_uri="http://localhost:8000/auth/github/callback"
)

# Register providers
auth_manager.register_provider("google", google_auth)
auth_manager.register_provider("github", github_auth)
```

2. **Implement OAuth Flow**

```python
@app.get("/auth/google/login")
async def google_login():
    authorization_url = google_auth.get_authorization_url(
        state="random-secure-state"  # Implement secure state handling
    )
    return RedirectResponse(authorization_url)

@app.get("/auth/google/callback")
async def google_callback(code: str, state: str):
    # Validate state
    validate_oauth_state(state)
    
    result = await auth_manager.authenticate(
        "/api/user/profile",
        {"google": {"code": code}}
    )
    
    if not result.success:
        raise HTTPException(401, "Authentication failed")
    
    # Get user info from result
    user_info = result.metadata["user_info"]
    
    return {
        "message": "Logged in with Google",
        "email": user_info["email"],
        "name": user_info["name"],
        "access_token": result.access_token
    }
```

## Advanced Usage Guide

### Combining Authentication Methods

1. **Require Multiple Methods (AND Strategy)**

```python
# Require both JWT and session authentication
auth_manager.add_requirement(
    "/api/admin/*",
    providers=["jwt", "session"],
    strategy=AuthStrategy.ALL,
    scopes=["admin"]
)

# Example request handler
@app.post("/api/admin/action")
async def admin_action(auth = Depends(auth_manager.requires_auth)):
    if "admin" not in auth.metadata.get("scopes", []):
        raise HTTPException(403, "Insufficient permissions")
    return {"message": "Admin action successful"}
```

2. **Allow Alternative Methods (OR Strategy)**

```python
# Allow any authentication method
auth_manager.add_requirement(
    "/api/user/*",
    providers=["jwt", "session", "google"],
    strategy=AuthStrategy.ANY
)
```

3. **Optional Authentication**

```python
# Add optional authentication methods
auth_manager.add_requirement(
    "/api/public/*",
    providers=["jwt"],
    optional_providers=["session", "google"]
)
```

### Custom Authentication Providers

1. **Create a Custom Provider**

```python
from fastsecure import AuthenticationProvider, AuthenticationResult
from typing import Dict, Any, Set

class APIKeyAuthProvider(AuthenticationProvider):
    def __init__(self, api_keys: Dict[str, str]):
        self.api_keys = api_keys
    
    def get_required_credentials(self) -> Set[str]:
        return {"api_key"}
    
    async def authenticate(
        self,
        credentials: Dict[str, Any]
    ) -> AuthenticationResult:
        api_key = credentials.get("api_key")
        
        if api_key not in self.api_keys:
            return AuthenticationResult(
                success=False,
                provider=self.provider_name,
                metadata={"error": "Invalid API key"}
            )
        
        return AuthenticationResult(
            success=True,
            provider=self.provider_name,
            user_id=self.api_keys[api_key],
            metadata={"api_key": api_key}
        )
    
    async def validate_authentication(
        self,
        auth_data: Dict[str, Any]
    ) -> bool:
        return auth_data.get("api_key") in self.api_keys
```

2. **Register and Use Custom Provider**

```python
# Initialize with API keys
api_key_auth = APIKeyAuthProvider({
    "key1": "user1",
    "key2": "user2"
})

# Register provider
auth_manager.register_provider("apikey", api_key_auth)

# Add requirement
auth_manager.add_requirement(
    "/api/service/*",
    providers=["apikey"]
)
```

### Storage Backends

1. **Implement Custom Session Storage**

```python
from fastsecure import SessionStore
from typing import Dict, Any, List, Optional
from datetime import datetime

class CustomSessionStore(SessionStore):
    async def create_session(
        self,
        user_id: int,
        session_id: str,
        expires_at: datetime,
        metadata: Dict[str, Any]
    ) -> bool:
        # Implement session creation
        pass
    
    async def get_session(
        self,
        session_id: str
    ) -> Optional[Dict[str, Any]]:
        # Implement session retrieval
        pass
    
    async def update_session(
        self,
        session_id: str,
        metadata: Dict[str, Any]
    ) -> bool:
        # Implement session update
        pass
    
    async def delete_session(
        self,
        session_id: str
    ) -> bool:
        # Implement session deletion
        pass
    
    async def get_user_sessions(
        self,
        user_id: int
    ) -> List[Dict[str, Any]]:
        # Implement user sessions retrieval
        pass
```

## Security Best Practices

1. **JWT Security**
   - Use strong secret keys
   - Set appropriate token expiration times
   - Implement token refresh securely
   - Use HTTPS for token transmission

2. **Session Security**
   - Enable secure cookie attributes
   - Implement session timeout
   - Limit concurrent sessions
   - Clean up expired sessions

3. **OAuth Security**
   - Validate OAuth state parameter
   - Use HTTPS for callbacks
   - Validate token scopes
   - Handle user data securely

4. **General Security**
   - Implement rate limiting
   - Use secure password handling
   - Log security events
   - Regular security audits

## Troubleshooting

Common issues and solutions:

1. **Token Validation Fails**
   - Check token expiration
   - Verify secret keys match
   - Ensure correct token format

2. **Session Issues**
   - Verify storage backend connection
   - Check session timeout settings
   - Validate cookie settings

3. **OAuth Problems**
   - Confirm OAuth credentials
   - Check redirect URI configuration
   - Verify state parameter handling

## Contributing

We welcome contributions! Here's how you can help:

1. **Code Contributions**
   - Fork the repository
   - Create a feature branch
   - Submit a pull request

2. **Bug Reports**
   - Use the issue tracker
   - Provide reproduction steps
   - Include relevant logs

3. **Documentation**
   - Improve examples
   - Fix typos
   - Add tutorials

4. **Feature Requests**
   - Describe the feature
   - Explain use cases
   - Provide examples

## License

This project is licensed under the MIT License - see the LICENSE file for details.