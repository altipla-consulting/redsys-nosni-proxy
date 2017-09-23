package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	log "github.com/sirupsen/logrus"

	"proxy/config"
)

func InsecureHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/health" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "redsys-nosni-proxy is ok")
		return
	}

	u := new(url.URL)
	*u = *r.URL
	u.Scheme = "https"
	u.Host = r.Host
	http.Redirect(w, r, u.String(), http.StatusMovedPermanently)
}

func SecureHandler(cnf *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "internal server error", http.StatusInternalServerError)
			log.WithFields(log.Fields{"error": err.Error()}).Error("input parsing failed")
			return
		}

		if r.URL.Path == "/blackhole" {
			fmt.Fprintln(w, "blackholed")
			log.WithFields(log.Fields{
				"signature-version":   r.FormValue("Ds_SignatureVersion"),
				"signature":           r.FormValue("Ds_Signature"),
				"merchant-parameters": r.FormValue("Ds_MerchantParameters"),
			}).Info("blackholed notification")
			return
		}

		if r.URL.Path == "/notification" {
			u, err := url.Parse(cnf.NotificationURL)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.WithFields(log.Fields{"error": err.Error()}).Error("invalid notification url")
				return
			}

			q := u.Query()
			q.Set("Ds_SignatureVersion", r.FormValue("Ds_SignatureVersion"))
			q.Set("Ds_Signature", r.FormValue("Ds_Signature"))
			q.Set("Ds_MerchantParameters", r.FormValue("Ds_MerchantParameters"))
			u.RawQuery = q.Encode()

			log.WithFields(log.Fields{
				"notification-url":    cnf.NotificationURL,
				"signature-version":   r.FormValue("Ds_SignatureVersion"),
				"signature":           r.FormValue("Ds_Signature"),
				"merchant-parameters": r.FormValue("Ds_MerchantParameters"),
			}).Info("sending notification")

			req, _ := http.NewRequest("POST", u.String(), nil)

			client := &http.Client{
				Timeout: 10 * time.Second,
				Transport: &http.Transport{
					// Disable HTTP/2 support, App Engine doesn't handle it correctly.
					TLSNextProto: make(map[string]func(authority string, c *tls.Conn) http.RoundTripper),
				},
			}
			resp, err := client.Do(req)
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.WithFields(log.Fields{"error": err.Error()}).Error("notification request failed")
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.WithFields(log.Fields{"status": resp.Status}).Error("notification request failed")
				return
			}

			if _, err := io.Copy(w, resp.Body); err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				log.WithFields(log.Fields{"error": err.Error()}).Error("copy response failed")
				return
			}

			log.WithFields(log.Fields{"signature": r.FormValue("Ds_Signature")}).Info("notification sent successfully")

			return
		}

		http.Error(w, "page not found", http.StatusNotFound)
		return
	}
}
