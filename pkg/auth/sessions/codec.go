package sessions

import (
	"encoding/json"
	"fmt"
	"time"
)

// loginStateJSON represents a serializable LoginState for Redis storage.
type loginStateJSON struct {
	UserID         string    `json:"userID"`
	Name           string    `json:"name"`
	Email          string    `json:"email"`
	Exp            time.Time `json:"exp"`
	RotateAt       time.Time `json:"rotateAt"`
	SessionToken   string    `json:"sessionToken"`
	RawToken       string    `json:"rawToken"`
	RefreshToken   string    `json:"refreshToken"`
	RefreshTokenID string    `json:"refreshTokenID"`
}

// MarshalLoginState serializes a LoginState to JSON bytes for storage.
func MarshalLoginState(ls *LoginState) ([]byte, error) {
	if ls == nil {
		return nil, fmt.Errorf("cannot marshal nil LoginState")
	}

	data := loginStateJSON{
		UserID:         ls.userID,
		Name:           ls.name,
		Email:          ls.email,
		Exp:            ls.exp,
		RotateAt:       ls.rotateAt,
		SessionToken:   ls.sessionToken,
		RawToken:       ls.rawToken,
		RefreshToken:   ls.refreshToken,
		RefreshTokenID: ls.refreshTokenID,
	}

	return json.Marshal(data)
}

// UnmarshalLoginState deserializes JSON bytes to a LoginState.
func UnmarshalLoginState(data []byte) (*LoginState, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot unmarshal empty data")
	}

	var decoded loginStateJSON
	if err := json.Unmarshal(data, &decoded); err != nil {
		return nil, fmt.Errorf("failed to unmarshal LoginState: %w", err)
	}

	ls := &LoginState{
		userID:         decoded.UserID,
		name:           decoded.Name,
		email:          decoded.Email,
		exp:            decoded.Exp,
		rotateAt:       decoded.RotateAt,
		sessionToken:   decoded.SessionToken,
		rawToken:       decoded.RawToken,
		refreshToken:   decoded.RefreshToken,
		refreshTokenID: decoded.RefreshTokenID,
		now:            time.Now,
	}

	return ls, nil
}
