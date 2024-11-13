package pdsql_test

import (
	"net"
	"testing"

	pdsql "github.com/wenerme/coredns-pdsql"
	"github.com/wenerme/coredns-pdsql/pdnsmodel"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	"golang.org/x/net/context"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type PowerDNSSQLTestCase struct {
	qname          string
	qtype          uint16   // the query type for the outgoing request
	expectedQType  []uint16 // the expected query type for the answers
	expectedCode   int
	expectedHeader []string // ownernames for the records in the answer section.
	expectedErr    error
	expectedRCode  int
	rrReply        []dns.RR
}

func runTestCases(t *testing.T, testRecords []*pdnsmodel.Record, tests []PowerDNSSQLTestCase) {
	t.Helper()

	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})

	if err != nil {
		t.Fatal(err)
	}

	p := pdsql.PowerDNSGenericSQLBackend{DB: db, AllowReverse: true, Fall: fall.F{}}
	if err := p.AutoMigrate(); err != nil {
		t.Fatal(err)
	}

	for _, r := range testRecords {
		if err := p.DB.Create(r).Error; err != nil {
			t.Fatal(err)
		}
	}

	ctx := context.TODO()

	for i, tc := range tests {
		t.Logf("Running test %d\n", i)
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(tc.qname), tc.qtype)

		observed := dnstest.NewRecorder(&test.ResponseWriter{})
		code, err := p.ServeDNS(ctx, observed, req)

		if err != tc.expectedErr {
			t.Errorf("Test %d: Expected error %v, but got %v", i, tc.expectedErr, err)
		}
		if code != tc.expectedCode {
			t.Errorf("Test %d: Expected status code %d, but got %d", i, tc.expectedCode, code)
		}

		if observed.Msg.Answer == nil && len(tc.rrReply) > 0 {
			t.Errorf("Test %d: Expected answer section, but got nil", i)
		}

		if observed.Msg.Rcode != tc.expectedRCode {
			t.Errorf("Test %d: Expected RCode %d, but got %d", i, tc.expectedRCode, observed.Msg.Rcode)
		}

		if len(tc.rrReply) != len(observed.Msg.Answer) {
			t.Errorf("Test %d: Expected replies of length %d, but got length %d", i, len(tc.rrReply), len(observed.Msg.Answer))
		}

		t.Logf("Authoritative: %v\n", observed.Msg.Authoritative)

		for j, answer := range observed.Msg.Answer {
			t.Logf("Checking answer[%d] rrtype: %d\n", j, answer.Header().Rrtype)

			if answer.Header().Rrtype != tc.expectedQType[j] {
				t.Errorf("Test %d: Expected type %d, but got %d", i, tc.qtype, answer.Header().Rrtype)
			}
		}

		for j, expected := range tc.expectedHeader {
			if len(observed.Msg.Answer) <= j {
				t.Errorf("Test %d: Expected %d answers in header, but got %d", i, len(tc.rrReply), len(observed.Msg.Answer))
				continue
			}

			actual := observed.Msg.Answer[j].Header().Name
			if actual != expected {
				t.Errorf("Test %d: Expected answer %s in header %d, but got %s", i, expected, j, actual)
			}

		}

		for j, testExpected := range tc.rrReply {
			t.Logf("Checking test %d, reply %d\n", i, j)
			if len(observed.Msg.Answer) <= j {
				t.Errorf("Test %d: Expected %d answers in reply, but got %d", i, len(tc.rrReply), len(observed.Msg.Answer))
				continue
			}

			t.Logf("Observed answer type: %T\n", observed.Msg.Answer[j])

			switch observed.Msg.Answer[j].(type) {
			case *dns.A:
				expectedRR := testExpected.(*dns.A)
				observedRR := observed.Msg.Answer[j].(*dns.A)

				if !expectedRR.A.Equal(observedRR.A) {
					t.Errorf("Test %d: Expected A reply %s, but got %s", j, expectedRR.A, observedRR.A)
				}

			case *dns.CNAME:
				expectedRR := testExpected.(*dns.CNAME)
				observedRR := observed.Msg.Answer[j].(*dns.CNAME)

				if expectedRR.Target != observedRR.Target {
					t.Errorf("Test %d: Expected CNAME reply %s, but got %s", j, expectedRR.Target, observedRR.Target)
				}

			case *dns.TXT:
				expectedRR := testExpected.(*dns.TXT)
				observedRR := observed.Msg.Answer[j].(*dns.TXT)

				if len(expectedRR.Txt) != len(observedRR.Txt) {
					t.Errorf("Test %d: Expected TXT reply of length %d, but got length %d", j, len(expectedRR.Txt), len(observedRR.Txt))
				}
				for ctr := range expectedRR.Txt {
					if expectedRR.Txt[ctr] != observedRR.Txt[ctr] {
						t.Errorf("Test %d: Expected TXT reply ctr=%d to be %s, but got %s", j, ctr, expectedRR.Txt[ctr], observedRR.Txt[ctr])
					}
				}

			case *dns.MX:
				expectedRR := testExpected.(*dns.MX)
				observedRR := observed.Msg.Answer[j].(*dns.MX)

				if expectedRR.Mx != observedRR.Mx {
					t.Errorf("Test %d: Expected MX reply %s, but got %s", j, expectedRR.Mx, observedRR.Mx)
				}

			case *dns.SRV:
				expectedRR := testExpected.(*dns.SRV)
				observedRR := observed.Msg.Answer[j].(*dns.SRV)

				if (expectedRR.Target != observedRR.Target) ||
					(expectedRR.Port != observedRR.Port) ||
					(expectedRR.Priority != observedRR.Priority) ||
					(expectedRR.Weight != observedRR.Weight) {

					t.Errorf(
						"Test %d: Expected SRV reply target=%s, priority=%d, weight=%d, port=%d, "+
							"but got target=%s, priority=%d, weight=%d, port=%d",
						j, expectedRR.Target, expectedRR.Priority, expectedRR.Weight, expectedRR.Port,
						observedRR.Target, observedRR.Priority, observedRR.Weight, observedRR.Port,
					)
				}

			case *dns.PTR:
				expectedRR := testExpected.(*dns.PTR)
				observedRR := observed.Msg.Answer[j].(*dns.PTR)

				if expectedRR.Ptr != observedRR.Ptr {
					t.Errorf("Test %d: Expected PTR reply %s, but got %s", j, expectedRR.Ptr, observedRR.Ptr)
				}

			default:
				t.Errorf("Test %d: Unexpected RR type %T", j, observed.Msg.Answer[j])
			}
		}
	}
}

func TestPowerDNSSQL(t *testing.T) {

	testRecords := []*pdnsmodel.Record{
		{Name: "example.org", Type: "A", Content: "192.168.1.1", Ttl: 3600},
		{Name: "cname.example.org", Type: "CNAME", Content: "example.org.", Ttl: 3600},
		{Name: "example.org", Type: "TXT", Content: "Example Response Text", Ttl: 3600},
		{Name: "multi.example.org", Type: "A", Content: "192.168.1.2", Ttl: 7200},
		{Name: "multi.example.org", Type: "A", Content: "192.168.1.3", Ttl: 7200},
		{Name: "example.org", Type: "MX", Content: "10 mail.example.org.", Ttl: 3600},
		{Name: "example.org", Type: "MX", Content: "20 mail2.example.org.", Ttl: 3600},
		{Name: "_xmpp._tcp.example.org", Type: "SRV", Content: "10 10 5269 example.org.", Ttl: 3600},
	}

	tests := []PowerDNSSQLTestCase{
		{
			qname:          "example.org.",
			qtype:          dns.TypeA,
			expectedQType:  []uint16{dns.TypeA},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.A{A: net.ParseIP("192.168.1.1")}},
		},
		{
			qname:          "cname.example.org.",
			qtype:          dns.TypeCNAME,
			expectedQType:  []uint16{dns.TypeCNAME},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"cname.example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.CNAME{Target: "example.org."}},
		},
		{
			qname:          "example.org.",
			qtype:          dns.TypeTXT,
			expectedQType:  []uint16{dns.TypeTXT},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.TXT{Txt: []string{"Example Response Text"}}},
		},
		{
			qname:          "multi.example.org.",
			qtype:          dns.TypeA,
			expectedQType:  []uint16{dns.TypeA, dns.TypeA},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"multi.example.org.", "multi.example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply: []dns.RR{&dns.A{A: net.ParseIP("192.168.1.2")},
				&dns.A{A: net.ParseIP("192.168.1.3")}},
		},
		{
			qname:          "example.org",
			qtype:          dns.TypeMX,
			expectedQType:  []uint16{dns.TypeMX, dns.TypeMX},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"example.org.", "example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.MX{Mx: "mail.example.org.", Preference: 10}, &dns.MX{Mx: "mail2.example.org.", Preference: 20}},
		},
		{
			qname:          "_xmpp._tcp.example.org.",
			qtype:          dns.TypeSRV,
			expectedQType:  []uint16{dns.TypeSRV},
			expectedCode:   dns.RcodeSuccess,
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			expectedHeader: []string{"_xmpp._tcp.example.org."},
			rrReply:        []dns.RR{&dns.SRV{Target: "example.org.", Priority: 10, Weight: 10, Port: 5269}},
		},
		{
			qname:          "eXamPlE.org.",
			qtype:          dns.TypeA,
			expectedQType:  []uint16{dns.TypeA},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.A{A: net.ParseIP("192.168.1.1")}},
		},
		{
			qname:          "1.1.168.192.in-addr.arpa.",
			qtype:          dns.TypePTR,
			expectedQType:  []uint16{dns.TypePTR},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"1.1.168.192.in-addr.arpa."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.PTR{Ptr: "example.org."}},
		},
	}

	runTestCases(t, testRecords, tests)

}

func TestWildcardMatch(t *testing.T) {

	tests := []struct {
		pattern  string
		name     string
		expected bool
	}{
		{"*.example.org.", "example.org.", false},
		{"a.example.org.", "a.example.org.", true},
		{"*.example.org.", "a.example.org.", true},
		{"*.example.org.", "abcd.example.org.", true},
	}

	for i, tc := range tests {
		act := pdsql.WildcardMatch(tc.name, tc.pattern)
		if tc.expected != act {
			t.Errorf("Test %d: Expected  %v, but got %v", i, tc.expected, act)
		}
	}
}

func TestReverse(t *testing.T) {
	testRecords := []*pdnsmodel.Record{
		{Name: "example.org", Type: "A", Content: "192.168.1.1", Ttl: 3600},
		{Name: "1.1.168.192.in-addr.arpa", Type: "PTR", Content: "example.org.", Ttl: 3600},
		{Name: "second.example.org", Type: "A", Content: "192.168.1.2", Ttl: 3600},
	}

	tests := []PowerDNSSQLTestCase{
		{
			qname:          "1.1.168.192.in-addr.arpa.",
			qtype:          dns.TypePTR,
			expectedQType:  []uint16{dns.TypePTR},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"1.1.168.192.in-addr.arpa."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.PTR{Ptr: "example.org."}},
		},
		{
			qname:          "2.1.168.192.in-addr.arpa",
			qtype:          dns.TypePTR,
			expectedQType:  []uint16{dns.TypePTR},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"2.1.168.192.in-addr.arpa."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.PTR{Ptr: "second.example.org."}},
		},
		{
			qname:          "3.1.168.192.in-addr.arpa",
			qtype:          dns.TypePTR,
			expectedQType:  []uint16{dns.TypePTR},
			expectedHeader: []string{},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeNameError,
			rrReply:        []dns.RR{},
		},
	}

	runTestCases(t, testRecords, tests)
}

func TestCname(t *testing.T) {
	testRecords := []*pdnsmodel.Record{
		{Name: "example.org", Type: "CNAME", Content: "2.example.org.", Ttl: 3600},
		{Name: "2.example.org", Type: "CNAME", Content: "3.example.org.", Ttl: 3600},
		{Name: "3.example.org", Type: "A", Content: "192.168.1.1", Ttl: 3600},
	}

	tests := []PowerDNSSQLTestCase{
		{
			qname:          "example.org",
			qtype:          dns.TypeA,
			expectedQType:  []uint16{dns.TypeCNAME, dns.TypeCNAME, dns.TypeA},
			expectedCode:   dns.RcodeSuccess,
			expectedHeader: []string{"example.org."},
			expectedErr:    nil,
			expectedRCode:  dns.RcodeSuccess,
			rrReply:        []dns.RR{&dns.CNAME{Target: "2.example.org."}, &dns.CNAME{Target: "3.example.org."}, &dns.A{A: net.ParseIP("192.168.1.1")}},
		},
	}

	runTestCases(t, testRecords, tests)
}
