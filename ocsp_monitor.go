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
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type Work struct {
	timeout time.Duration
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
	random_serial_test OCSPTest
}

func checkRedirectURL(req *http.Request, via []*http.Request) error {
	// Fixup incorrectly encoded redirect URLs
	req.URL.RawQuery = strings.Replace(req.URL.RawQuery, " ", "%20", -1)
	return nil
}

func (w *Work) CustomFlags() string {
	flag.DurationVar(&w.timeout, "timeout", 30 * time.Second, "HTTP timeout")
	return fmt.Sprintf("  timeout: %s\n", w.timeout)
}

func (w *Work) Init() {
	w.transport = http.Transport { TLSClientConfig: &tls.Config { InsecureSkipVerify: true } }
	w.http_client = http.Client { CheckRedirect: checkRedirectURL, Timeout: w.timeout, Transport: &w.transport }
}

// Work.Begin
// Do any DB stuff that needs to happen before a batch of work.
func (w *Work) Begin(db *sql.DB) {
	var err error

	w.get_issuer_cert_statement, err = db.Prepare(`
SELECT c.CERTIFICATE
	FROM ca_certificate cac, certificate c
	WHERE cac.CA_ID = $1
		AND cac.CERTIFICATE_ID = c.ID
	LIMIT 1
`)
	checkErr(err)

	// TODO: Also check that this cert does contain the OCSP Responder URL we're testing?
	w.get_test_cert_statement, err = db.Prepare(`
SELECT c.ID, c.CERTIFICATE
	FROM certificate c
	WHERE c.ISSUER_CA_ID = $1
		AND x509_notAfter(c.CERTIFICATE) > statement_timestamp() AT TIME ZONE 'UTC'
	LIMIT 1
`)
	checkErr(err)
}

// Work.End
// Do any DB stuff that needs to happen after a batch of work.
func (w *Work) End() {
	w.get_issuer_cert_statement.Close()
	w.get_test_cert_statement.Close()
}

// Work.Prepare()
// Prepare the driving SELECT query.
func (w *Work) SelectQuery(batch_size int) string {
	return fmt.Sprintf(`
SELECT orp.CA_ID, orp.URL
	FROM ocsp_responder orp
	WHERE orp.NEXT_CHECKS_DUE < statement_timestamp() AT TIME ZONE 'UTC'
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

		if !wi.get_test.result.Valid {
			wi.get_test.result.String = error_message
			wi.get_test.result.Valid = true
		}
		if !wi.post_test.result.Valid {
			wi.post_test.result.String = error_message
			wi.post_test.result.Valid = true
		}
		if !wi.random_serial_test.result.Valid {
			wi.random_serial_test.result.String = error_message
			wi.random_serial_test.result.Valid = true
		}

		panic(err)
	}
}

func (wi *WorkItem) setErr(err error, ocsp_test *OCSPTest) bool {
	if err == nil {
		return false
	} else {
		error_message := ""
		last_colon := strings.LastIndex(err.Error(), ": ")
		if last_colon != -1 {
			error_message = err.Error()[last_colon+2:]
		} else {
			error_message = err.Error()
		}

		ocsp_test.result.String = error_message
		ocsp_test.result.Valid = true
		return true
	}
}

func (wi *WorkItem) doOCSP(method string, ocsp_req_bytes []byte, ocsp_test *OCSPTest, cert *x509.Certificate, issuer *x509.Certificate) {
	var req *http.Request
	var err error
	if method == "GET" {
		request_url := wi.ocsp_responder_url
		if !strings.HasSuffix(request_url, "/") {
			request_url += "/"
		}
		request_url += url.QueryEscape(base64.StdEncoding.EncodeToString(ocsp_req_bytes))
		req, err = http.NewRequest(method, request_url, nil)
	} else if method == "POST" {
		req, err = http.NewRequest(method, wi.ocsp_responder_url, bytes.NewReader(ocsp_req_bytes))
	} else {
		return
	}

	if wi.setErr(err, ocsp_test) {
		return
	}

	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Connection", "close")
	req.Header.Set("User-Agent", "crt.sh")
	time_start := time.Now()
	resp, err := wi.work.http_client.Do(req)
	if err != nil && resp == nil {
		ocsp_test.duration = time.Since(time_start)
		if wi.setErr(err, ocsp_test) {
			return
		}
	}
	defer resp.Body.Close()

	ocsp_test.dump, err = httputil.DumpResponse(resp, true)
	if wi.setErr(err, ocsp_test) {
		return
	}

	body, err := ioutil.ReadAll(resp.Body)
	ocsp_test.duration = time.Since(time_start)
	if wi.setErr(err, ocsp_test) {
		return
	}

	ocsp_resp, err := ocsp.ParseResponseForCert(body, cert, issuer)
	if err != nil {
		if resp.StatusCode != 200 {
			ocsp_test.result.Valid = true
			ocsp_test.result.String = fmt.Sprintf("HTTP %d", resp.StatusCode)
			return
		} else if wi.setErr(err, ocsp_test) {
			return
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

func (wi *WorkItem) RandomSerialTest(issuer *x509.Certificate) {
	var publicKeyInfo struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	_, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &publicKeyInfo)
	if wi.setErr(err, &wi.random_serial_test) {
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
	if wi.setErr(err, &wi.random_serial_test) {
		return
	}
	ocsp_req.SerialNumber = big.NewInt(0)
	ocsp_req.SerialNumber.SetBytes(random_serial[:])

	ocsp_req_bytes, err := ocsp_req.Marshal()
	if wi.setErr(err, &wi.random_serial_test) {
		return
	}

	wi.doOCSP("POST", ocsp_req_bytes, &wi.random_serial_test, nil, issuer)
}

func (wi *WorkItem) GETTest(issuer *x509.Certificate, cert *x509.Certificate) {
	ocsp_req_bytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if wi.setErr(err, &wi.get_test) {
		return
	}

	wi.doOCSP("GET", ocsp_req_bytes, &wi.get_test, cert, issuer)
}

func (wi *WorkItem) POSTTest(issuer *x509.Certificate, cert *x509.Certificate) {
	ocsp_req_bytes, err := ocsp.CreateRequest(cert, issuer, nil)
	if wi.setErr(err, &wi.post_test) {
		return
	}

	wi.doOCSP("POST", ocsp_req_bytes, &wi.post_test, cert, issuer)
}

// WorkItem.Perform()
// Do the work for one item.
func (wi *WorkItem) Perform(db *sql.DB, w *Work) {
	wi.work = w
	wi.get_test.result.Valid = false
	wi.get_test.dump = wi.get_test.dump[:0]
	wi.get_test.duration = 0
	wi.post_test.result.Valid = false
	wi.post_test.dump = wi.get_test.dump[:0]
	wi.post_test.duration = 0
	wi.random_serial_test.result.Valid = false
	wi.random_serial_test.dump = wi.random_serial_test.dump[:0]
	wi.random_serial_test.duration = 0

	// Fetch and parse the/an Issuer certificate.
	err := w.get_issuer_cert_statement.QueryRow(wi.ca_id).Scan(&wi.issuer_cert)
	wi.checkErr(err)
	issuer, err := x509.ParseCertificate(wi.issuer_cert)
	wi.checkErr(err)

	// Test how the responder deals with an unissued serial number.
	wi.RandomSerialTest(issuer)
	log.Printf("Unissued: %s [%d, %s]", wi.random_serial_test.result.String, wi.ca_id, wi.ocsp_responder_url)

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
	wi.GETTest(issuer, cert)
	log.Printf("GET: %s [%d, %s]", wi.get_test.result.String, wi.ca_id, wi.ocsp_responder_url)

	// Test how the responder deals with a POST request for an unexpired cert.
	wi.POSTTest(issuer, cert)
	log.Printf("POST: %s [%d, %s]", wi.post_test.result.String, wi.ca_id, wi.ocsp_responder_url)
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
		RANDOM_SERIAL_RESULT=$8,
		RANDOM_SERIAL_DUMP=$9,
		RANDOM_SERIAL_DURATION=$10
	WHERE CA_ID=$11
		AND URL=$12
`
}

// WorkItem.Update()
// Update the DB with the results of the work for this item.
func (wi *WorkItem) Update(update_statement *sql.Stmt) (sql.Result, error) {
	return update_statement.Exec(
		wi.test_cert_id,
		wi.get_test.result, wi.get_test.dump, wi.get_test.duration,
		wi.post_test.result, wi.post_test.dump, wi.post_test.duration,
		wi.random_serial_test.result, wi.random_serial_test.dump, wi.random_serial_test.duration,
		wi.ca_id, wi.ocsp_responder_url)
}
