package main

import (
	"net/http"

	"github.com/simonhege/server"
)

type OpenIDConfiguration struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksUri                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	ResponseModesSupported           []string `json:"response_modes_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IdTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported                  []string `json:"claims_supported"`
}

func (a *app) handleOpenIDConfiguration(w http.ResponseWriter, req *http.Request) {
	server.RenderJSON(w, a.oidcConfig)
}

func NewOpenIDConfiguration(issuer string, baseURL string) *OpenIDConfiguration {
	return &OpenIDConfiguration{
		Issuer:                issuer,
		AuthorizationEndpoint: baseURL + "/authorize",
		TokenEndpoint:         baseURL + "/token",
		UserinfoEndpoint:      baseURL + "/userinfo",
		JwksUri:               baseURL + "/.well-known/jwks.json",
		ScopesSupported: []string{
			"openid",
			"email",
		},
		ResponseTypesSupported: []string{
			"code",
			"id_token",
			"id_token token",
		},
		ResponseModesSupported: []string{
			"query",
			"fragment",
		},
		GrantTypesSupported: []string{
			"authorization_code",
			"implicit",
		},
		SubjectTypesSupported: []string{
			"public", // TODO switch to "pairwise" for better privacy
		},
		IdTokenSigningAlgValuesSupported: []string{
			"RS256",
		},
		ClaimsSupported: []string{
			"sub",
			"iss",
			"aud",
			"exp",
			"iat",
			"nbf",
			"auth_time",
			"email",
			"email_verified",
			"name",
			"picture",
		},
	}
}
