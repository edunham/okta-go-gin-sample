package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	verifier "github.com/okta/okta-jwt-verifier-golang"
	oauthUtils "github.com/okta/okta-jwt-verifier-golang/utils"
	"github.com/thanhpk/randstr"
	"golang.org/x/oauth2"
)

var sessionStore *sessions.CookieStore

func initSessionStore() {
	secret := os.Getenv("SESSION_SECRET")
	if secret == "" {
		log.Fatal("SESSION_SECRET environment variable is required")
	}
	sessionStore = sessions.NewCookieStore([]byte(secret))
	sessionStore.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}
}

// IndexHandler serves the index.html page
func IndexHandler(c *gin.Context) {
	log.Println("Loading main page")

	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}

	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the index.gohtml template
		"index.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func LoginHandler(c *gin.Context) {
	c.Header("Cache-Control", "no-cache") // See https://github.com/okta/samples-golang/issues/20

	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	// Generate a random state parameter for CSRF security
	oauthState := randstr.Hex(16)
	oauthNonce := randstr.Hex(16)
	
	// Create the PKCE code verifier and code challenge
	oauthCodeVerifier, err := oauthUtils.GenerateCodeVerifierWithLength(50)
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
	// get sha256 hash of the code verifier
	oauthCodeChallenge := oauthCodeVerifier.CodeChallengeS256()

	session.Values["oauth_state"] = oauthState
	session.Values["oauth_nonce"] = oauthNonce
	session.Values["oauth_code_verifier"] = oauthCodeVerifier.String()

	session.Save(c.Request, c.Writer)

	redirectURI := oktaOauthConfig.AuthCodeURL(
		oauthState,
		oauth2.SetAuthURLParam("code_challenge", oauthCodeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("nonce", oauthNonce),
	)

	c.Redirect(http.StatusFound, redirectURI)
}

func LogoutHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, fmt.Errorf("the state was not as expected"))
		return
	}

	if accessToken, ok := session.Values["access_token"].(string); ok && accessToken != "" {
		revokeToken(accessToken)
	}

	delete(session.Values, "access_token")

	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")
}

func revokeToken(token string) {
	issuer := os.Getenv("OKTA_OAUTH2_ISSUER")
	clientID := os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	clientSecret := os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")

	revokeURL := issuer + "/v1/revoke"

	data := url.Values{}
	data.Set("token", token)
	data.Set("token_type_hint", "access_token")

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", revokeURL, nil)
	if err != nil {
		log.Printf("Failed to create revoke request: %v", err)
		return
	}

	req.SetBasicAuth(clientID, clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	encodedData := data.Encode()
	req.Body = io.NopCloser(strings.NewReader(encodedData))
	req.ContentLength = int64(len(encodedData))

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Failed to revoke token: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("Token revocation returned status: %d", resp.StatusCode)
	}
}

func ProfileHandler(c *gin.Context) {
	errorMsg := ""

	profile, err := getProfileData(c.Request)

	if err != nil {
		errorMsg = err.Error()
	}
	c.HTML(
		// Set the HTTP status to 200 (OK)
		http.StatusOK,
		// Use the profile.gohtml template
		"profile.gohtml",
		// Pass the data that the page uses
		gin.H{
			"Profile":         profile,
			"IsAuthenticated": isAuthenticated(c.Request),
			"Error":           errorMsg,
		},
	)
}

func getProfileData(r *http.Request) (map[string]string, error) {
	m := make(map[string]string)

	session, err := sessionStore.Get(r, "okta-hosted-login-session-store")

	if err != nil || session.Values["access_token"] == nil || session.Values["access_token"] == "" {
		return m, nil
	}

	reqUrl := os.Getenv("OKTA_OAUTH2_ISSUER") + "/v1/userinfo"

	req, err := http.NewRequest("GET", reqUrl, nil)
	if err != nil {
		return m, err
	}

	h := req.Header
	h.Add("Authorization", "Bearer "+session.Values["access_token"].(string))
	h.Add("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return m, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return m, err
	}

	err = json.Unmarshal(body, &m)
	if err != nil {
		return m, err
	}

	return m, nil
}

func AuthCodeCallbackHandler(c *gin.Context) {
	session, err := sessionStore.Get(c.Request, "okta-hosted-login-session-store")
	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
		return
	}

	// Check the state that was returned in the query string is the same as the above state
	if c.Query("state") == "" || c.Query("state") != session.Values["oauth_state"] {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("the state was not as expected"))
		return
	}

	storedNonce := session.Values["oauth_nonce"]
	storedCodeVerifier := session.Values["oauth_code_verifier"]

	delete(session.Values, "oauth_state")
	delete(session.Values, "oauth_nonce")
	delete(session.Values, "oauth_code_verifier")

	if c.Query("error") != "" {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("authorization server returned an error: %s", c.Query("error")))
		return
	}
	// Make sure the code was provided
	if c.Query("code") == "" {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("authorization code not received"))
		return
	}

	if storedCodeVerifier == nil {
		c.AbortWithError(http.StatusForbidden, fmt.Errorf("code verifier not found in session"))
		return
	}

	token, err := oktaOauthConfig.Exchange(
		context.Background(),
		c.Query("code"),
		oauth2.SetAuthURLParam("code_verifier", storedCodeVerifier.(string)),
	)
	if err != nil {
		c.AbortWithError(http.StatusUnauthorized, err)
		return
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		c.AbortWithError(http.StatusUnauthorized, fmt.Errorf("id token missing from OAuth2 token"))
		return
	}

	var expectedNonce string
	if storedNonce != nil {
		expectedNonce = storedNonce.(string)
	}

	_, err = verifyToken(rawIDToken, expectedNonce)

	if err != nil {
		c.AbortWithError(http.StatusForbidden, err)
		return
	}

	session.Values["access_token"] = token.AccessToken
	session.Save(c.Request, c.Writer)

	c.Redirect(http.StatusFound, "/")
}

func verifyToken(t string, nonce string) (*verifier.Jwt, error) {
	tv := map[string]string{}
	tv["aud"] = os.Getenv("OKTA_OAUTH2_CLIENT_ID")
	if nonce != "" {
		tv["nonce"] = nonce
	}
	jv := verifier.JwtVerifier{
		Issuer:           os.Getenv("OKTA_OAUTH2_ISSUER"),
		ClaimsToValidate: tv,
	}

	result, err := jv.New().VerifyIdToken(t)
	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	if result != nil {
		return result, nil
	}

	return nil, fmt.Errorf("token could not be verified")
}
