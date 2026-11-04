package http

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type appleAppSiteAssociation []byte

func newAppleAppSiteAssociation(appIDs []string) (appleAppSiteAssociation, error) {
	var document struct {
		WebCredentials struct {
			Apps []string `json:"apps"`
		} `json:"webcredentials"`
	}

	document.WebCredentials.Apps = appIDs

	body, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("apple app site association: %w", err)
	}

	return body, nil
}

func (a appleAppSiteAssociation) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(a)
}
