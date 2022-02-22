/* crt.sh: ocsp_monitor - OCSP Responder Monitor
 * Written by Rob Stradling
 * Copyright (C) 2017-2021 Sectigo Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package main

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"encoding/base64"
	"flag"
	"fmt"
	"golang.org/x/crypto/ocsp"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type config struct {
	// Common configuration parameters shared by all processors.
	ConnInfo string
	ConnOpen int
	ConnIdle int
	ConnLife duration
	Interval duration
	Batch int
	Concurrent int
	// Processor-specific config.
	Chunk int
	HTTPTimeout duration
}

type Work struct {
	c *config
	db *sql.DB
	transport http.Transport
	http_client http.Client
	get_issuer_cert_statement *sql.Stmt
	get_test_cert_statement *sql.Stmt
}

type OCSPTest struct {
	result sql.NullString
	duration time.Duration
	dump []byte
}

type WorkItem struct {
	work *Work
	ca_id int32
	ocsp_responder_url string
	issuer_cert []byte
	test_cert_id sql.NullString
	test_cert []byte
	get_test OCSPTest
	post_test OCSPTest
	get_random_serial_test OCSPTest
	post_random_serial_test OCSPTest
	forward_slashes_test OCSPTest
	sha256_certid_test OCSPTest
	unencoded_plus_test OCSPTest
}

func checkRedirectURL(req *http.Request, via []*http.Request) error {
	// Fixup incorrectly encoded redirect URLs
	req.URL.RawQuery = strings.Replace(req.URL.RawQuery, " ", "%20", -1)
	return nil
}

// tomlConfig.DefineCustomFlags() and tomlConfig.PrintCustomFlags()
// Specify command-line flags that are specific to this processor.
func (c *config) DefineCustomFlags() {
	flag.DurationVar(&c.HTTPTimeout.Duration, "httptimeout", c.HTTPTimeout.Duration, "HTTP timeout")
}
func (c *config) PrintCustomFlags() string {
	return fmt.Sprintf("httptimeout:%s", c.HTTPTimeout.Duration)
}

func (w *Work) Init(c *config) {
	w.c = c
	w.transport = http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { CheckRedirect: checkRedirectURL, Timeout: c.HTTPTimeout.Duration, Transport: &w.transport }

	var err error

	w.get_issuer_cert_statement, err = w.db.Prepare(`
SELECT c.CERTIFICATE
	FROM ca_certificate cac, certificate c
	WHERE cac.CA_ID = $1
		AND cac.CERTIFICATE_ID = c.ID
	LIMIT 1
`)
	checkErr(err)

	w.get_test_cert_statement, err = w.db.Prepare(`
SELECT c.ID, c.CERTIFICATE
	FROM certificate c
			LEFT OUTER JOIN ca_certificate cac ON (c.ID = cac.CERTIFICATE_ID)
	WHERE c.ISSUER_CA_ID = $1
		AND coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) > now() AT TIME ZONE 'UTC'
		AND c.ISSUER_CA_ID != coalesce(cac.CA_ID, -1)
	ORDER BY coalesce(x509_notAfter(c.CERTIFICATE), 'infinity'::timestamp) DESC
	LIMIT 1
`)
	checkErr(err)
}

// Work.Begin
// Do any DB stuff that needs to happen before a batch of work.
func (w *Work) Begin(db *sql.DB) {
}

// Work.End
// Do any DB stuff that needs to happen after a batch of work.
func (w *Work) End() {
}

// Work.Exit
// One-time program exit code.
func (w *Work) Exit() {
	w.get_issuer_cert_statement.Close()
	w.get_test_cert_statement.Close()
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT orp.CA_ID, orp.URL
	FROM ocsp_responder orp
	WHERE orp.NEXT_CHECKS_DUE < now() AT TIME ZONE 'UTC'
		AND orp.CA_ID != -1
	ORDER BY orp.NEXT_CHECKS_DUE
	LIMIT %d
`, batch_size)
}

// WorkItem.Parse()
// Parse one SELECTed row to configure one work item.
func (wi *WorkItem) Parse(rs *sql.Rows) error {
	return rs.Scan(&wi.ca_id, &wi.ocsp_responder_url)
}

func (wi *WorkItem) checkErr(err error) {
	if err != nil {
		error_message := ""
		last_colon := strings.LastIndex(err.Error(), ": ")
		if last_colon != -1 {
			error_message = err.Error()[last_colon+2:]
		} else {
			error_message = err.Error()
		}

		if (!wi.get_test.result.Valid) && (wi.get_test.result.String == "") {
			wi.get_test.result.String = error_message
			wi.get_test.result.Valid = true
		}
		if (!wi.post_test.result.Valid) && (wi.post_test.result.String == "") {
			wi.post_test.result.String = error_message
			wi.post_test.result.Valid = true
		}
		if (!wi.get_random_serial_test.result.Valid) && (wi.get_random_serial_test.result.String == "") {
			wi.get_random_serial_test.result.String = error_message
			wi.get_random_serial_test.result.Valid = true
		}
		if (!wi.post_random_serial_test.result.Valid) && (wi.post_random_serial_test.result.String == "") {
			wi.post_random_serial_test.result.String = error_message
			wi.post_random_serial_test.result.Valid = true
		}
		if (!wi.forward_slashes_test.result.Valid) && (wi.forward_slashes_test.result.String == "") {
			wi.forward_slashes_test.result.String = error_message
			wi.forward_slashes_test.result.Valid = true
		}
		if (!wi.sha256_certid_test.result.Valid) && (wi.sha256_certid_test.result.String == "") {
			wi.sha256_certid_test.result.String = error_message
			wi.sha256_certid_test.result.Valid = true
		}
		if (!wi.unencoded_plus_test.result.Valid) && (wi.unencoded_plus_test.result.String == "") {
			wi.unencoded_plus_test.result.String = error_message
			wi.unencoded_plus_test.result.Valid = true
		}

		panic(err)
	}
}

func (wi *WorkItem) setErr(err error, error_context string, ocsp_test *OCSPTest) bool {
	if err == nil {
		return false
	} else {
		error_message := ""
		if error_context != "" {
			error_message = error_context + " => "
		}
		last_colon := strings.LastIndex(err.Error(), ": ")
		if last_colon != -1 {
			error_message += err.Error()[last_colon+2:]
		} else {
			error_message += err.Error()
		}

		ocsp_test.result.String = error_message
		ocsp_test.result.Valid = true
		return true
	}
}

func (wi *WorkItem) doOCSP(method string, ocsp_req_bytes []byte, ocsp_test *OCSPTest, cert *x509.Certificate, issuer *x509.Certificate, encode_pluses bool) {
	var req *http.Request
	var err error
	if method == "GET" {
		request_url := wi.ocsp_responder_url
		if !strings.HasSuffix(request_url, "/") {
			request_url += "/"
		}
		if encode_pluses {
			request_url += url.QueryEscape(base64.StdEncoding.EncodeToString(ocsp_req_bytes))
		} else {
			request_url += url.PathEscape(base64.StdEncoding.EncodeToString(ocsp_req_bytes))
		}
		req, err = http.NewRequest(method, request_url, nil)
	} else if method == "POST" {
		req, err = http.NewRequest(method, wi.ocsp_responder_url, bytes.NewReader(ocsp_req_bytes))
	} else {
		return
	}

	if wi.setErr(err, "http.NewRequest", ocsp_test) {
		return
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "crt.sh")
	time_start := time.Now()
	resp, err := wi.work.http_client.Do(req)
	if err != nil && resp == nil {
		ocsp_test.duration = time.Since(time_start)
		if wi.setErr(err, "http_client.Do", ocsp_test) {
			return
		}
	}
	defer resp.Body.Close()

	ocsp_test.dump, err = httputil.DumpResponse(resp, true)
	if wi.setErr(err, "httputil.DumpResponse", ocsp_test) {
		return
	}

	body, err := io.ReadAll(resp.Body)
	ocsp_test.duration = time.Since(time_start)
	if wi.setErr(err, "io.ReadAll", ocsp_test) {
		return
	}

	ocsp_resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		if resp.StatusCode != 200 {
			ocsp_test.result.Valid = true
			ocsp_test.result.String = fmt.Sprintf("HTTP %d", resp.StatusCode)
			return
		} else {
			error_context := ""
			switch err.(type) {
				case ocsp.ResponseError:
				default: error_context = "ocsp.ParseResponseForCert"
			}
			if wi.setErr(err, error_context, ocsp_test) {
				return
			}
		}
	}

	if ocsp_resp.Status == ocsp.Good {
		ocsp_test.result.String = "Good"
	} else if ocsp_resp.Status == ocsp.Unknown {
		ocsp_test.result.String = "Unknown"
	} else if ocsp_resp.Status == ocsp.Revoked {
		ocsp_test.result.String = fmt.Sprintf("Revoked|%v|%d", ocsp_resp.RevokedAt, ocsp_resp.RevocationReason)
	} else {
		ocsp_test.result.String = "Unexpected Status!"
	}
	ocsp_test.result.Valid = true
}

func (wi *WorkItem) RandomSerialTest(method string, ocsp_test *OCSPTest, issuer *x509.Certificate) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if wi.setErr(err, "asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo)", ocsp_test) {
		return
	}

	var ocsp_req ocsp.Request
	ocsp_req.HashAlgorithm = crypto.Hash(crypto.SHA1)
	h := ocsp_req.HashAlgorithm.New()
	h.Write(publicKeyInfo.PublicKey.RightAlign())
	ocsp_req.IssuerKeyHash = h.Sum(nil)

	h.Reset()
	h.Write(issuer.RawSubject)
	ocsp_req.IssuerNameHash = h.Sum(nil)

	random_serial := [20]byte{}
	copy(random_serial[:], "crt.sh")
	_, err = rand.Read(random_serial[6:])
	if wi.setErr(err, "rand.Read", ocsp_test) {
		return
	}
	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes(random_serial[:])

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if wi.setErr(err, "ocsp_req.Marshal", ocsp_test) {
		return
	}

	wi.doOCSP(method, ocsp_req_bytes, ocsp_test, nil, issuer, true)
}

func (wi *WorkItem) ForwardSlashesTest(method string, ocsp_test *OCSPTest, issuer *x509.Certificate) {
	var ocsp_req ocsp.Request
	ocsp_req.HashAlgorithm = crypto.Hash(crypto.SHA1)
	ocsp_req.IssuerKeyHash = make([]byte, 20)
	ocsp_req.IssuerNameHash = make([]byte, 20)

	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes([]byte{0x03, 0xFF, 0xFC})	// https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/cMegyySSqhM/m/G7s5tFR4BAAJ

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if wi.setErr(err, "ocsp_req.Marshal", ocsp_test) {
		return
	}

	wi.doOCSP(method, ocsp_req_bytes, ocsp_test, nil, issuer, true)
}

func (wi *WorkItem) UnencodedPlusTest(method string, ocsp_test *OCSPTest, issuer *x509.Certificate) {
	var ocsp_req ocsp.Request
	ocsp_req.HashAlgorithm = crypto.Hash(crypto.SHA1)
	ocsp_req.IssuerKeyHash = make([]byte, 20)
	ocsp_req.IssuerNameHash = make([]byte, 20)

	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes([]byte{0x03, 0xFE, 0xFC})	// https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/cMegyySSqhM/m/zcJwbdNnAwAJ

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if wi.setErr(err, "ocsp_req.Marshal", ocsp_test) {
		return
	}

	wi.doOCSP(method, ocsp_req_bytes, ocsp_test, nil, issuer, false)
}

func (wi *WorkItem) IssuedSerialTest(method string, ocsp_test *OCSPTest, issuer *x509.Certificate, cert *x509.Certificate, hash_algorithm crypto.Hash) {
	opt := ocsp.RequestOptions{Hash: hash_algorithm}
	ocsp_req_bytes, err := ocsp.CreateRequest(cert, issuer, &opt)
	if wi.setErr(err, "ocsp.CreateRequest", ocsp_test) {
		return
	}

	wi.doOCSP(method, ocsp_req_bytes, ocsp_test, cert, issuer, true)
}

// WorkItem.Perform()
// Do the work for one item.
func (wi *WorkItem) Perform(db *sql.DB, w *Work) {
	wi.work = w
	wi.get_test.result.Valid = false
	wi.get_test.result.String = ""
	wi.get_test.dump = wi.get_test.dump[:0]
	wi.get_test.duration = 0
	wi.post_test.result.Valid = false
	wi.post_test.result.String = ""
	wi.post_test.dump = wi.post_test.dump[:0]
	wi.post_test.duration = 0
	wi.get_random_serial_test.result.Valid = false
	wi.get_random_serial_test.result.String = ""
	wi.get_random_serial_test.dump = wi.get_random_serial_test.dump[:0]
	wi.get_random_serial_test.duration = 0
	wi.post_random_serial_test.result.Valid = false
	wi.post_random_serial_test.result.String = ""
	wi.post_random_serial_test.dump = wi.post_random_serial_test.dump[:0]
	wi.post_random_serial_test.duration = 0
	wi.forward_slashes_test.result.Valid = false
	wi.forward_slashes_test.result.String = ""
	wi.forward_slashes_test.dump = wi.forward_slashes_test.dump[:0]
	wi.forward_slashes_test.duration = 0
	wi.sha256_certid_test.result.Valid = false
	wi.sha256_certid_test.result.String = ""
	wi.sha256_certid_test.dump = wi.sha256_certid_test.dump[:0]
	wi.sha256_certid_test.duration = 0
	wi.unencoded_plus_test.result.Valid = false
	wi.unencoded_plus_test.result.String = ""
	wi.unencoded_plus_test.dump = wi.unencoded_plus_test.dump[:0]
	wi.unencoded_plus_test.duration = 0

	// Fetch and parse the/an Issuer certificate.
	err := w.get_issuer_cert_statement.QueryRow(wi.ca_id).Scan(&wi.issuer_cert)
	wi.checkErr(err)
	issuer, err := x509.ParseCertificate(wi.issuer_cert)
	wi.checkErr(err)

	// Test how the responder deals with a GET request for an unissued serial number.
	wi.RandomSerialTest("GET", &wi.get_random_serial_test, issuer)
	log.Printf("Unissued: %s [%d, %s]", wi.get_random_serial_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with a POST request for an unissued serial number.
	wi.RandomSerialTest("POST", &wi.post_random_serial_test, issuer)
	log.Printf("Unissued: %s [%d, %s]", wi.post_random_serial_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with multiple forward-slashes.
	wi.ForwardSlashesTest("GET", &wi.forward_slashes_test, issuer)
	log.Printf("Forward-slashes: %s [%d, %s]", wi.forward_slashes_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with non-URL-encoded "+" characters.
	wi.UnencodedPlusTest("GET", &wi.unencoded_plus_test, issuer)
	log.Printf("Unencoded-plus: %s [%d, %s]", wi.unencoded_plus_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Get an unexpired certificate issued by this issuer.
	err = w.get_test_cert_statement.QueryRow(wi.ca_id).Scan(&wi.test_cert_id, &wi.test_cert)
	if err == sql.ErrNoRows {
		log.Printf("GET/POST: No test cert available [%d, %s]", wi.ca_id, wi.ocsp_responder_url)
		return
	}
	wi.checkErr(err)
	cert, err := x509.ParseCertificate(wi.test_cert)
	wi.checkErr(err)

	// Test how the responder deals with a GET request for an unexpired cert.
	wi.IssuedSerialTest("GET", &wi.get_test, issuer, cert, crypto.SHA1)
	log.Printf("GET: %s [%d, %s]", wi.get_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with a POST request for an unexpired cert.
	wi.IssuedSerialTest("POST", &wi.post_test, issuer, cert, crypto.SHA1)
	log.Printf("POST: %s [%d, %s]", wi.post_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with SHA-256 CertIDs.
	wi.IssuedSerialTest("GET", &wi.sha256_certid_test, issuer, cert, crypto.SHA256)
	log.Printf("GET(SHA-256): %s [%d, %s]", wi.sha256_certid_test.result.String, wi.ca_id, wi.ocsp_responder_url)
}

// Work.UpdateStatement()
// Prepare the UPDATE statement to be run after processing each work item.
func (w *Work) UpdateStatement() string {
	return `
UPDATE ocsp_responder
	SET LAST_CHECKED=statement_timestamp() AT TIME ZONE 'UTC',
		NEXT_CHECKS_DUE=statement_timestamp() AT TIME ZONE 'UTC' + interval '1 hour',
		TESTED_CERTIFICATE_ID=$1,
		GET_RESULT=$2,
		GET_DUMP=$3,
		GET_DURATION=$4,
		POST_RESULT=$5,
		POST_DUMP=$6,
		POST_DURATION=$7,
		GET_RANDOM_SERIAL_RESULT=$8,
		GET_RANDOM_SERIAL_DUMP=$9,
		GET_RANDOM_SERIAL_DURATION=$10,
		POST_RANDOM_SERIAL_RESULT=$11,
		POST_RANDOM_SERIAL_DUMP=$12,
		POST_RANDOM_SERIAL_DURATION=$13,
		FORWARD_SLASHES_RESULT=$14,
		FORWARD_SLASHES_DUMP=$15,
		FORWARD_SLASHES_DURATION=$16,
		SHA256_CERTID_RESULT=$17,
		SHA256_CERTID_DUMP=$18,
		SHA256_CERTID_DURATION=$19,
		UNENCODED_PLUS_RESULT=$20,
		UNENCODED_PLUS_DUMP=$21,
		UNENCODED_PLUS_DURATION=$22
	WHERE CA_ID=$23
		AND URL=$24
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item.
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	return update_statement.Exec(
		wi.test_cert_id,
		wi.get_test.result, wi.get_test.dump, wi.get_test.duration,
		wi.post_test.result, wi.post_test.dump, wi.post_test.duration,
		wi.get_random_serial_test.result, wi.get_random_serial_test.dump, wi.get_random_serial_test.duration,
		wi.post_random_serial_test.result, wi.post_random_serial_test.dump, wi.post_random_serial_test.duration,
		wi.forward_slashes_test.result, wi.forward_slashes_test.dump, wi.forward_slashes_test.duration,
		wi.sha256_certid_test.result, wi.sha256_certid_test.dump, wi.sha256_certid_test.duration,
		wi.unencoded_plus_test.result, wi.unencoded_plus_test.dump, wi.unencoded_plus_test.duration,
		wi.ca_id, wi.ocsp_responder_url)
}
