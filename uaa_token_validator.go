package cfcommon

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sync"

	jwt "github.com/dgrijalva/jwt-go"
)

// UAAOAuthGrant used to parse JSON for an access token from UAA server
type UAAOAuthGrant struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	Scope        string `json:"scope"`
	RefreshToken string `json:"refresh_token"`
	JTI          string `json:"jti"`
}

// FetchAccessToken sends data to endpoint to fetch a token
// Return grant object.
func (lh *UAAClient) FetchAccessToken(clientID, clientSecret string, postData url.Values) (*UAAOAuthGrant, error) {
	req, err := http.NewRequest(http.MethodPost, lh.UAAURL+"/oauth/token", bytes.NewReader([]byte(postData.Encode())))
	if err != nil {
		return nil, err
	}
	// Older versions of CF require this to be set via header, not in POST data
	// WONTFIX: we query escape these per OAuth spec. Apparently UAA does not - might cause an issue if they don't fix their end
	req.SetBasicAuth(url.QueryEscape(clientID), url.QueryEscape(clientSecret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New("bad status code")
	}

	var og UAAOAuthGrant
	err = json.NewDecoder(resp.Body).Decode(&og)
	resp.Body.Close()
	if err != nil {
		return nil, err
	}

	return &og, nil
}

// UAAClient will validate access tokens against a UAA instance, caching keys as required
type UAAClient struct {
	// UAAURL is the URL to UAA, e.g. https://uaa.system.example.com
	UAAURL string

	// Internal, lock for cached public keys
	cachedKeysLock sync.RWMutex

	// Public key map
	cachedKeys map[string]*rsa.PublicKey
}

type cfApisResponse struct {
	Links struct {
		UAA struct {
			URL string `json:"href"`
		} `json:"uaa"`
	} `json:"links"`
}

// NewUAAClientFromAPIURL looks up, via the apiEndpoint, the correct UAA address and returns a client
func NewUAAClientFromAPIURL(apiEndpoint string) (*UAAClient, error) {
	resp, err := http.Get(apiEndpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var m cfApisResponse
	err = json.NewDecoder(resp.Body).Decode(&m)
	if err != nil {
		return nil, err
	}

	uaaURL := m.Links.UAA.URL
	if uaaURL == "" {
		return nil, errors.New("no uaa URL returned")
	}

	return &UAAClient{UAAURL: uaaURL}, nil
}

func (lh *UAAClient) GetAuthorizeEndpoint() string {
	return lh.UAAURL + "/oauth/authorize"
}

// ExchangeBearerTokenForClientToken takes a bearer token (such as that returned by CF), and exchanges via
// the API auth flow, for an OAuthGrant for the specified clientID. The clientSecret here is really not a secret.
func (lh *UAAClient) ExchangeBearerTokenForClientToken(clientID, clientSecret, bearerLine string) (*UAAOAuthGrant, error) {
	req, err := http.NewRequest(http.MethodPost, lh.UAAURL+"/oauth/authorize", bytes.NewReader([]byte(url.Values(map[string][]string{
		"client_id":     {clientID},
		"response_type": {"code"},
	}).Encode())))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", bearerLine)

	resp, err := (&http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusFound {
		return nil, errors.New("expected 302 back from UAA")
	}
	u, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		return nil, err
	}
	authCode := u.Query().Get("code")
	if authCode == "" {
		return nil, errors.New("expected  auth code back from UAA")
	}

	return lh.FetchAccessToken(clientID, clientSecret, url.Values(map[string][]string{
		"response_type": {"token"},
		"grant_type":    {"authorization_code"},
		"code":          {authCode},
	}))
}

// Return public key for a given key ID, if we have it, else nil is returned
func (lh *UAAClient) pubKeyForID(kid string) *rsa.PublicKey {
	lh.cachedKeysLock.RLock()
	defer lh.cachedKeysLock.RUnlock()

	if lh.cachedKeys == nil {
		return nil
	}

	rv, ok := lh.cachedKeys[kid]
	if !ok {
		return nil
	}

	return rv
}

// Contact UAA to fetch latest public key, and if it matches the key ID requested,
// then return it, else an error will be returned.
func (lh *UAAClient) fetchAndSaveLatestKey(idWanted string) (*rsa.PublicKey, error) {
	resp, err := http.Get(lh.UAAURL + "/token_key")
	if err != nil {
		return nil, err
	}

	var dd struct {
		ID  string `json:"kid"`
		PEM string `json:"value"`
	}
	err = json.NewDecoder(resp.Body).Decode(&dd)
	resp.Body.Close()

	if err != nil {
		return nil, err
	}

	pk, err := jwt.ParseRSAPublicKeyFromPEM([]byte(dd.PEM))
	if err != nil {
		return nil, err
	}

	lh.cachedKeysLock.Lock()
	defer lh.cachedKeysLock.Unlock()

	if lh.cachedKeys == nil {
		lh.cachedKeys = make(map[string]*rsa.PublicKey)
	}

	// With old verions of CF, the KID will be empty. That seems OK as it'll now be empty here too.
	lh.cachedKeys[dd.ID] = pk

	if dd.ID != idWanted {
		return nil, errors.New("still can't find it")
	}

	return pk, nil
}

// Find the public key to verify the JWT, and check the algorithm.
func (lh *UAAClient) cfKeyFunc(t *jwt.Token) (interface{}, error) {
	// Ensure that RS256 is used. This might seem overkill to care,
	// but since the JWT spec actually allows a None algorithm which
	// we definitely don't want, so instead we whitelist what we will allow.
	if t.Method.Alg() != "RS256" {
		return nil, errors.New("bad token9")
	}

	// Get Key ID
	kid, ok := t.Header["kid"]
	if !ok {
		kid = "" // some versions of CloudFoundry don't return a key ID - if so, let's just hope for the best
	}

	kidS, ok := kid.(string)
	if !ok {
		return nil, errors.New("bad token 11")
	}

	rv := lh.pubKeyForID(kidS)
	if rv != nil {
		return rv, nil
	}

	rv, err := lh.fetchAndSaveLatestKey(kidS)
	if err != nil {
		return nil, err
	}

	return rv, nil
}

// ValidateAccessToken will validate the given access token, ensure it matches the client ID, and return the claims reported within.
func (lh *UAAClient) ValidateAccessToken(at, expectedClientID string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(at, lh.cfKeyFunc)
	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, errors.New("bad token 1")
	}

	mapClaims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("bad token 2")
	}

	if !mapClaims.VerifyIssuer(lh.UAAURL+"/oauth/token", true) {
		return nil, errors.New("bad token 3")
	}

	// Never, ever, ever, skip a client ID check (common error)
	cid, _ := mapClaims["client_id"].(string)
	if cid != expectedClientID {
		return nil, errors.New("very bad token 4")
	}

	return mapClaims, nil
}
