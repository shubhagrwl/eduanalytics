# RBAC Implementation with Casbin

## Overview

This project implements Role-Based Access Control (RBAC) using Casbin, a powerful authorization library. The RBAC system enforces access control based on user roles (admin, teacher, student) for different API endpoints.

## Architecture

### Components

1. **Casbin Model** (`configs/casbin_model.conf`): Defines the RBAC model structure
2. **Casbin Policy** (`configs/casbin_policy.csv`): Contains role-permission mappings
3. **Casbin Middleware** (`internal/app/api/middleware/casbin/casbin.go`): Enforces authorization
4. **Role Constants** (`internal/app/constants/constants.go`): Defines role constants

## Roles and Permissions

### Roles

- **admin**: Full access to all endpoints
- **teacher**: Access to teaching and reporting features
- **student**: Limited access to student-specific features
- **public**: Access only to authentication endpoints

### Permission Matrix

| Endpoint | Admin | Teacher | Student | Public |
|----------|-------|---------|---------|--------|
| `/auth/register` | ✓ | ✗ | ✗ | ✓ |
| `/auth/login` | ✓ | ✗ | ✗ | ✓ |
| `/refresh` | ✓ | ✓ | ✓ | ✗ |
| `/logout` | ✓ | ✓ | ✓ | ✗ |
| `/quizzes` (POST) | ✓ | ✓ | ✗ | ✗ |
| `/responses` (POST) | ✓ | ✓ | ✓ | ✗ |
| `/student-performance` (GET) | ✓ | ✓ | ✓ | ✗ |
| `/classroom-engagement` (GET) | ✓ | ✓ | ✗ | ✗ |
| `/content-effectiveness` (GET) | ✓ | ✓ | ✗ | ✗ |
| `/ws/quiz` (GET) | ✓ | ✓ | ✓ | ✗ |

## How It Works

### 1. Request Flow

```
Request → Authentication Middleware → Casbin Middleware → Controller
```

- **Authentication Middleware**: Validates JWT token and extracts user claims
- **Casbin Middleware**: Checks if user's role has permission for the requested resource
- **Controller**: Processes the request if authorized

### 2. Casbin Model

The RBAC model uses the following structure:

```conf
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
```

- **sub**: Subject (role)
- **obj**: Object (API path)
- **act**: Action (HTTP method)

### 3. Policy File Format

```csv
p, role, path, method
g, role, role
```

Example:
```csv
p, teacher, /quizzes, POST
g, teacher, teacher
```

## Setup Instructions

### 1. Install Dependencies

Run the following command to install Casbin and its dependencies:

```bash
go mod tidy
```

### 2. Configure Policies

Edit `configs/casbin_policy.csv` to add or modify permissions:

```csv
# Format: p, role, path, method
p, new_role, /new-endpoint, GET
```

### 3. Update User Roles

Ensure users have the correct role in the database:

```sql
UPDATE users SET role = 'teacher' WHERE email = 'teacher@example.com';
UPDATE users SET role = 'student' WHERE email = 'student@example.com';
UPDATE users SET role = 'admin' WHERE email = 'admin@example.com';
```

## Adding New Permissions

### Step 1: Add Policy Rule

Add a new line to `configs/casbin_policy.csv`:

```csv
p, teacher, /new-endpoint, POST
```

### Step 2: Reload Policies

The enforcer automatically loads policies on startup. For runtime updates, use:

```go
enforcer.LoadPolicy()
```

### Step 3: Apply to Routes

Add the Casbin middleware to your route:

```go
protected.POST("/new-endpoint", newController.NewMethod)
```

## Testing RBAC

### Test as Different Roles

1. **Login as Teacher**:
   ```bash
   curl -X POST http://localhost:8080/api/v1/auth/login \
     -H "Content-Type: application/json" \
     -d '{"email":"teacher@example.com","password":"password"}'
   ```

2. **Access Protected Endpoint**:
   ```bash
   curl -X POST http://localhost:8080/api/v1/quizzes \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{"title":"New Quiz"}'
   ```

3. **Expected Response**:
   - ✓ Teacher: 200 OK (success)
   - ✗ Student: 403 Forbidden (access denied)

## Troubleshooting

### Issue: "Access Denied" for Valid User

**Solution**: Check if:
1. User role is correctly set in database
2. Policy exists in `casbin_policy.csv`
3. Path and method match exactly

### Issue: "Casbin enforcer initialization failed"

**Solution**: Verify that:
1. `configs/casbin_model.conf` exists
2. `configs/casbin_policy.csv` exists
3. File paths are correct

### Issue: Public endpoints require authentication

**Solution**: Ensure public routes use Casbin middleware without authentication:

```go
v1.POST(REGISTER, casbinmw.Authorizer(enforcer), oAuthController.Register)
```

## Advanced Configuration

### Database-Based Policies

To use database for policies instead of CSV:

1. Install database adapter:
   ```bash
   go get github.com/casbin/gorm-adapter/v3
   ```

2. Initialize adapter:
   ```go
   adapter, _ := gormadapter.NewAdapter("postgres", "connection_string")
   enforcer, _ := casbin.NewEnforcer("model.conf", adapter)
   ```

### Dynamic Policy Management

Add policies at runtime:

```go
// Add policy
enforcer.AddPolicy("teacher", "/new-endpoint", "GET")

// Remove policy
enforcer.RemovePolicy("student", "/restricted", "POST")

// Save policies
enforcer.SavePolicy()
```

## Security Best Practices

1. **Principle of Least Privilege**: Grant minimum required permissions
2. **Regular Audits**: Review policies periodically
3. **Role Hierarchy**: Use role inheritance for complex scenarios
4. **Logging**: Monitor access denied events for security analysis

## References

- [Casbin Documentation](https://casbin.org/docs/overview)
- [RBAC Model](https://casbin.org/docs/rbac)
- [Casbin with Gin](https://casbin.org/docs/middlewares)


