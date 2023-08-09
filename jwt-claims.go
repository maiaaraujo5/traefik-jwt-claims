package traefik_jwt_claims

import (
	"context"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

type Config struct {
	SecretKey                 string `json:"secretKey,omitempty"`
	NameOfAuthorizationHeader string `json:"nameOfAuthorizationHeader,omitempty"`
	NameOfUserIDInToken       string `json:"nameOfUserIDInToken,omitempty"`
	NameForUserIDInHeader     string `json:"nameForUserIDInHeader,omitempty"`
	ExcludePaths              string `json:"excludePaths,omitempty"`
}

func CreateConfig() *Config {
	return &Config{}
}

type TraefikJWTClaims struct {
	next                      http.Handler
	name                      string
	SecretKey                 string
	NameOfAuthorizationHeader string
	NameOfUserIDInToken       string
	NameForUserIDInHeader     string
	ExcludePaths              map[string]struct{}
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {

	return &TraefikJWTClaims{
		next:                      next,
		name:                      name,
		SecretKey:                 config.SecretKey,
		NameOfAuthorizationHeader: config.NameOfAuthorizationHeader,
		NameOfUserIDInToken:       config.NameOfUserIDInToken,
		NameForUserIDInHeader:     config.NameForUserIDInHeader,
		ExcludePaths: func() map[string]struct{} {
			paths := make(map[string]struct{})
			for _, path := range strings.Split(config.ExcludePaths, ",") {
				paths[path] = struct{}{}
			}
			return paths
		}(),
	}, nil
}

func (t *TraefikJWTClaims) ServeHTTP(resp http.ResponseWriter, request *http.Request) {
	if t.pathShouldNotUseAuthentication(request.URL.Path) {
		t.next.ServeHTTP(resp, request)
		return
	}

	token, err := t.getToken(request.Header.Get(t.NameOfAuthorizationHeader))
	if err != nil || token == nil || !token.Valid {
		resp.WriteHeader(http.StatusUnauthorized)
		return
	}

	claims := token.Claims.(jwt.MapClaims)
	request.Header.Set(t.NameForUserIDInHeader, claims[t.NameOfUserIDInToken].(string))
	t.next.ServeHTTP(resp, request)
}

func (t *TraefikJWTClaims) getToken(stringToken string) (*jwt.Token, error) {
	token, err := jwt.Parse(stringToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("método de assinatura inválido: %v", token.Header["alg"])
		}
		return []byte(t.SecretKey), nil
	})

	return token, err

}

func (t *TraefikJWTClaims) pathShouldNotUseAuthentication(path string) bool {
	_, ok := t.ExcludePaths[path]
	return ok
}
