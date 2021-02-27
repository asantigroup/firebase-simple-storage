package firebasestorage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/flowchartsman/retry"
)

// Storage represent a Firebase Storage client
type Storage struct {
	Bucket       string
	Token        string
	RefreshToken string
	APIKey       string
}

func (s *Storage) resource(path string) string {
	return fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o?name=%s", s.Bucket, path)
}

func (s *Storage) auth(req *http.Request) {
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.Token))
}

func (s *Storage) request(ctx context.Context, auth bool, verb string, loc string, b []byte, file string) (map[string]interface{}, error) {
	retrier := retry.NewRetrier(7, time.Second, 64*time.Second)
	var res *http.Response
	err := retrier.RunContext(ctx, func(ctx context.Context) error {
		var data io.Reader
		if b != nil {
			data = bytes.NewBuffer(b)
		}
		if file != "" {
			data, err := os.Open(file)
			if err != nil {
				// non-retryable error - stop now
				return retry.Stop(err)
			}
			defer data.Close()
		}
		req, err := http.NewRequest(verb, loc, data)
		if err != nil {
			return err
		}

		if auth {
			s.auth(req)
		}
		req.Header.Set("Content-Type", "application/json")
		req = req.WithContext(ctx)
		res, err = http.DefaultClient.Do(req)

		switch {
		case err != nil:
			// request error - return it
			log.Printf("Request error: %v", err)
			return err
		case res.StatusCode == 0 || res.StatusCode >= 500:
			// retryable StatusCode - return it
			log.Printf("Retryable HTTP status: %v", http.StatusText(res.StatusCode))
			return fmt.Errorf("Retryable HTTP status: %s", http.StatusText(res.StatusCode))
		case res.StatusCode != 200:
			// non-retryable error - stop now
			return retry.Stop(fmt.Errorf("Non-retryable HTTP status: %s", http.StatusText(res.StatusCode)))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	r := new(map[string]interface{})
	err = json.Unmarshal(body, &r)
	if err != nil {
		return nil, err
	}

	return *r, nil
}

// Object will fetch the storage object metadata from Firebase
func (s *Storage) Object(ctx context.Context, path string) (map[string]interface{}, error) {
	return s.request(ctx, true, "GET", s.resource(path), nil, "")
}

// Download will download a file from Firebase
// `path` - object path in firebase
// `toFile` - local file to write to
func (s *Storage) Download(ctx context.Context, path, toFile string) error {
	obj, err := s.Object(ctx, path)
	if err != nil {
		return err
	}
	downloadToken := obj["downloadTokens"].(string)

	out, err := os.Create(toFile)
	if err != nil {
		return err
	}
	defer out.Close()

	reader, err := s.Read(path, downloadToken)
	if err != nil {
		return err
	}
	defer reader.Close()

	_, err = io.Copy(out, reader)
	return err
}

// DownloadURL returns a convenience download url to a file.
// You can get the `downloadToken` under the `downloadTokens` field (notice
// plural) from `Storage.Object`, or immediately after a `Storeage.Put`.
func (s *Storage) DownloadURL(path, downloadToken string) string {
	return fmt.Sprintf("https://firebasestorage.googleapis.com/v0/b/%s/o/%s?alt=media&token=%s",
		s.Bucket,
		url.QueryEscape(path),
		downloadToken,
	)
}

// Read will read a file from Firebase storage, providing the bytes over an `io.ReadClose`
// `path` - object path in firebase
// `downloadToken` - a token retrieved from `Storage.Object`
func (s *Storage) Read(path, downloadToken string) (io.ReadCloser, error) {
	resp, err := http.Get(s.DownloadURL(path, downloadToken))
	return resp.Body, err
}

// Put will store a file in Firebase Storage
func (s *Storage) Put(ctx context.Context, file, path string) (map[string]interface{}, error) {
	res, err := s.request(ctx, true, "POST", s.resource(path), nil, file)
	if err != nil {
		return nil, err
	}
	return res, err
}

//Refresh will refresh your Firebase user access tokens. Typically these tokens are
//valid for an hour.
//
//You can call this when operations fail, when the time almost expires, or before
//every operation just to be safe.
func (s *Storage) Refresh(ctx context.Context) error {
	loc := fmt.Sprintf("https://securetoken.googleapis.com/v1/token?key=%s", s.APIKey)
	data := map[string]string{
		"grantType":    "refresh_token",
		"refreshToken": s.RefreshToken,
	}
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	res, err := s.request(ctx, false, "POST", loc, b, "")
	if err != nil {
		return err
	}

	accessToken := res["access_token"].(string)
	if accessToken != "" {
		s.Token = accessToken
	}
	refreshToken := res["refresh_token"].(string)
	if refreshToken != "" {
		s.RefreshToken = refreshToken
	}

	return nil
}
