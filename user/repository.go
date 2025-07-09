package user

import (
	"context"

	"github.com/google/uuid"
)

// UserReader defines read operations for user data
type UserReader interface {
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	Exists(ctx context.Context, email string) (bool, error)
}

// UserWriter defines write operations for user data
type UserWriter interface {
	Create(ctx context.Context, user *User) error
	Update(ctx context.Context, user *User) error
	Delete(ctx context.Context, id uuid.UUID) error
}

// UserRepository combines read and write operations
type UserRepository interface {
	UserReader
	UserWriter
}

// UserLister defines listing operations for users
type UserLister interface {
	List(ctx context.Context, limit, offset int) ([]*User, error)
	Count(ctx context.Context) (int, error)
}

// FullUserRepository combines all user repository operations
type FullUserRepository interface {
	UserRepository
	UserLister
}