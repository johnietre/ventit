package user

import "golang.org/x/crypto/bcrypt"

// User holds the information of an application user.
type User struct {
  // Id is the user's ID. Must be non-zero.
  Id uint64 `json:"id,omitempt"`
  // Username is the user's username. Must be unique.
  Username string `json:"username,omitempty"`
  // Email is the email address of the user.
  Email string `json:"email,omitempty"`
  // Anonymous is whether a user is anonymous to others or not.
  Anonymous bool `json:"anonymous,omitempty"`
}

func HashPassword(pwd string) (string, error) {
  pwdHash, err := bcrypt.GenerateFromPassword([]byte(pwd), bcrypt.DefaultCost)
  return string(pwdHash), err
}

func CheckPassword(pwd, hash string) bool {
  return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pwd)) == nil
}
