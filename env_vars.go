package cfcommon

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	cfenv "github.com/cloudfoundry-community/go-cfenv"
)

// EnvVars provides a convenient method to access environment variables
type EnvVars struct {
	path []EnvLookup
}

// String returns value for key if present, else returns defaultVal if not found
func (el *EnvVars) String(key, defaultVal string) string {
	rv, found := el.load(key)
	if !found {
		return defaultVal
	}
	return rv
}

// MustString will panic if value is not set, otherwise it returns the value.
func (el *EnvVars) MustString(key string) string {
	rv, found := el.load(key)
	if !found {
		panic(&ErrMissingEnvVar{Name: key})
	}
	return rv
}

// Bool looks for the key, and if found, parses it using strconv.ParseBool and returns
// the result. If not found, returns false. If found and won't parse, panics.
func (el *EnvVars) Bool(key string) bool {
	val, found := el.load(key)
	if !found {
		return false
	}

	rv, err := strconv.ParseBool(val)
	if err != nil {
		// invalid values will now return an error
		// previous behavior defaulted to false
		panic(err)
	}

	return rv
}

// load is an internal method that looks for a given key within
// all elements in the path, and if none found, returns "", false.
func (el *EnvVars) load(key string) (string, bool) {
	for _, env := range el.path {
		rv, found := env(key)
		if found {
			return rv, true
		}
	}
	return "", false
}

// NewDefaultEnvLookup will detect if running in a CloudFoundry app,
// and if so will look for an env variable named UPS_PATH which if specified,
// must be a ":" separated list of user-provided-services that will be searched
// in that order. If any are missing, a warning is printed, but no error occurs.
// In any case, env variables are always sourced from your local environment
// variables first.
func NewDefaultEnvLookup() *EnvVars {
	lookupPath := []EnvLookup{os.LookupEnv}

	app, err := cfenv.Current()
	if err == nil {
		for _, name := range strings.Split(os.Getenv("UPS_PATH"), ":") {
			lookupPath = append(lookupPath, NewEnvLookupFromCFAppNamedService(app, name))
		}
	}

	return NewEnvVarsFromPath(lookupPath...)
}

// NewEnvVarsFromPath create an EnvVars object, where the elements in the path
// are searched in order to load a given variable.
func NewEnvVarsFromPath(path ...EnvLookup) *EnvVars {
	return &EnvVars{path: path}
}

// EnvLookup must return the value for the given key and whether it was found or not
type EnvLookup func(key string) (string, bool)

// ErrMissingEnvVar is panicked if a MustGet fails.
type ErrMissingEnvVar struct {
	// Name of the key that was not found
	Name string
}

// Error returns an error string
func (err *ErrMissingEnvVar) Error() string {
	return fmt.Sprintf("missing env variable: %s", err.Name)
}

// NewEnvLookupFromCFAppNamedService looks for a CloudFoundry bound service
// with the given name, and will allow sourcing of environment variables
// from there. If no service is found, a warning is printed, but no error thrown.
func NewEnvLookupFromCFAppNamedService(cfApp *cfenv.App, namedService string) EnvLookup {
	var service *cfenv.Service
	if cfApp != nil {
		var err error
		service, err = cfApp.Services.WithName(namedService)
		if err != nil {
			// swallow error, as we'll print message below anyway, but ensure service hasn't been assigned to
			service = nil
		}
	}
	if service == nil {
		log.Printf("Warning: No bound service found with name: %s, will not be used for sourcing env variables.\n", namedService)
	}
	return func(name string) (string, bool) {
		if service == nil { // no service
			return "", false
		}
		serviceVar, found := service.Credentials[name]
		if !found {
			return "", false
		}
		serviceVarAsString, ok := serviceVar.(string)
		if !ok {
			log.Printf("Warning: variable found in service for %s, but unable to cast as string, so ignoring.\n", name)
			return "", false
		}
		return serviceVarAsString, true
	}
}
