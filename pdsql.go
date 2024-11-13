// Package pdsql implements a plugin that query powerdns database to resolve the coredns query
package pdsql

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/wenerme/coredns-pdsql/pdnsmodel"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/fall"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"gorm.io/gorm"
)

const Name = "pdsql"
const hostmaster = "hostmaster"
const defaultTtl = 360

type PowerDNSGenericSQLBackend struct {
	*gorm.DB
	Debug        bool
	Next         plugin.Handler
	Fall         fall.F
	AllowReverse bool
	Zones        []string
}

func (pdb PowerDNSGenericSQLBackend) Serial(state request.Request) uint32 {
	return uint32(time.Now().Unix())
}

func (pdb PowerDNSGenericSQLBackend) MinTtl(state request.Request) uint32 {
	// if pdb.Ttl == 0 {
	return defaultTtl
	// }
	// return pdb.Ttl
}

func (pdb PowerDNSGenericSQLBackend) findRecord(name string, types ...string) ([]*pdnsmodel.Record, error) {
	var records []*pdnsmodel.Record
	var appendRecords []*pdnsmodel.Record
	var cnameTypes []string

	name = strings.TrimSuffix(name, ".")

	query := pdb.DB.Where("name = ? AND disabled = ?", name, false)

	// Filter out empty strings from types
	filteredTypes := make([]string, 0, len(types))
	cnameFound := false
	for _, t := range types {
		if t != "" {
			filteredTypes = append(filteredTypes, t)
		}
		if t == "A" || t == "AAAA" {
			cnameTypes = append(cnameTypes, t)
		}
		if t == "CNAME" {
			cnameFound = true
		}
	}

	if len(cnameTypes) > 0 {
		cnameTypes = append(cnameTypes, "CNAME")
		if !cnameFound {
			filteredTypes = append(filteredTypes, "CNAME")
		}
	}

	// Add the IN clause only if filteredTypes is not empty
	if len(filteredTypes) > 0 {
		query = query.Where("type IN (?)", filteredTypes)
	}

	err := query.Find(&records).Error
	if err != nil {
		return nil, err
	}

	// If we have a CNAME, we need to recurse to get the A/AAAA record.
	// But, we only do this if the query was not just for the CNAME
	if len(cnameTypes) > 0 {
		for _, v := range records {
			if v.Type == "CNAME" {
				newRecords, err := pdb.findRecord(v.Content, cnameTypes...)
				if err != nil {
					if err != gorm.ErrRecordNotFound {
						return nil, err
					}
				}
				appendRecords = append(appendRecords, newRecords...)
			}
		}
	}

	return append(records, appendRecords...), nil
}

func (pdb PowerDNSGenericSQLBackend) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	// opt := plugin.Options{}
	state := request.Request{W: w, Req: r}
	zone := plugin.Zones(pdb.Zones).Matches(state.Name())
	qname := strings.ToLower(state.QName())

	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true

	var records []*pdnsmodel.Record

	queryType := state.Type()
	if state.QType() == dns.TypeANY {
		queryType = ""
	}

	records, err := pdb.findRecord(qname, queryType)
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			records, err = pdb.findRecord(qname, "SOA")
			if err == nil && len(records) > 0 {
				rr := new(dns.SOA)
				rr.Hdr = dns.RR_Header{Name: state.QName(), Rrtype: dns.TypeSOA, Class: state.QClass()}
				if ParseSOA(rr, records[0].Content) {
					a.Extra = append(a.Extra, rr)
				}
			}
		} else {
			return dns.RcodeServerFailure, err
		}
	} else {
		if len(records) == 0 && state.QType() == dns.TypePTR && pdb.AllowReverse {
			// if you have Reverse set to true, search A records when PTR is requested
			// an no PTR has been found yet
			var tmpRecords []*pdnsmodel.Record

			ipQname := strings.TrimSuffix(qname, ".")

			if strings.HasSuffix(ipQname, ".in-addr.arpa") {
				ipParts := strings.Split(ipQname, ".")
				if len(ipParts) >= 4 {
					ip := fmt.Sprintf("%s.%s.%s.%s", ipParts[3], ipParts[2], ipParts[1], ipParts[0])
					query := pdnsmodel.Record{Content: ip, Type: "A", Disabled: false}
					if err := pdb.Where(query).Find(&tmpRecords).Error; err != nil {
						if err == gorm.ErrRecordNotFound {
							return dns.RcodeNameError, nil
						}
						return dns.RcodeServerFailure, err
					}

					// munge the A records so they look like PTR records and we can send them back
					for _, v := range tmpRecords {
						// set ID=0 in case we accidentally save these
						v.ID = 0
						hostname := v.Name
						v.Name = qname
						v.Content = hostname
						v.Type = "PTR"
						records = append(records, v)
					}
				}
			}
		}

		// if we still have no records, and the query is for an A or AAAA record, check for a wildcard
		if len(records) == 0 {
			records, err = pdb.SearchWildcard(state.QName(), state.QType())
			if err != nil {
				return dns.RcodeServerFailure, err
			}
		}

		for _, v := range records {
			typ := dns.StringToType[v.Type]
			hrd := dns.RR_Header{Name: qname, Rrtype: typ, Class: state.QClass(), Ttl: v.Ttl}
			if !strings.HasSuffix(hrd.Name, ".") {
				hrd.Name += "."
			}
			rr := dns.TypeToRR[typ]()

			// todo support more type
			// this is enough for most query
			switch rr := rr.(type) {
			case *dns.SOA:
				rr.Hdr = hrd
				if !ParseSOA(rr, v.Content) {
					rr = nil
				}
			case *dns.A:
				rr.Hdr = hrd
				rr.A = net.ParseIP(v.Content)
			case *dns.AAAA:
				rr.Hdr = hrd
				rr.AAAA = net.ParseIP(v.Content)
			case *dns.TXT:
				rr.Hdr = hrd
				rr.Txt = []string{v.Content}
			case *dns.NS:
				rr.Hdr = hrd
				rr.Ns = v.Content
			case *dns.PTR:
				rr.Hdr = hrd
				// pdns don't need the dot but when we answer, we need it
				if strings.HasSuffix(v.Content, ".") {
					rr.Ptr = v.Content
				} else {
					rr.Ptr = v.Content + "."
				}
			case *dns.CNAME:
				rr.Hdr = hrd
				rr.Target = v.Content

			case *dns.MX:
				rr.Hdr = hrd
				parts := strings.Split(v.Content, " ")
				if len(parts) == 2 {
					preference, host := parts[0], parts[1]
					if pref, err := strconv.Atoi(preference); err == nil {
						rr.Preference = uint16(pref)
					} else {
						return dns.RcodeServerFailure, fmt.Errorf("invalid MX preference: %s", preference)
					}
					rr.Mx = host
				} else {
					return dns.RcodeServerFailure, fmt.Errorf("malformed MX record content: %s", v.Content)
				}

			case *dns.SRV:
				rr.Hdr = hrd
				parts := strings.Split(v.Content, " ")
				if len(parts) != 4 {
					return dns.RcodeServerFailure, fmt.Errorf("malformed SRV record content: %s - parts=%d", v.Content, len(parts))
				}
				if priority, err := strconv.Atoi(parts[0]); err == nil {
					rr.Priority = uint16(priority)
				} else {
					return dns.RcodeServerFailure, fmt.Errorf("invalid SRV priority: %s", parts[0])
				}
				if weight, err := strconv.Atoi(parts[1]); err == nil {
					rr.Weight = uint16(weight)
				} else {
					return dns.RcodeServerFailure, fmt.Errorf("invalid SRV weight: %s", parts[1])
				}
				if port, err := strconv.Atoi(parts[2]); err == nil {
					rr.Port = uint16(port)
				} else {
					return dns.RcodeServerFailure, fmt.Errorf("invalid SRV port: %s", parts[2])
				}
				rr.Target = parts[3]
			default:
				// drop unsupported
			}

			if rr == nil {
				// invalid record
			} else {
				a.Answer = append(a.Answer, rr)
			}
		}
	}

	if len(a.Answer) == 0 {
		if pdb.Fall.Through(state.Name()) {
			return plugin.NextOrFailure(pdb.Name(), pdb.Next, ctx, w, r)
		} else {
			// Return NXDOMAIN if fallthrough is not enabled
			m := new(dns.Msg)
			m.SetRcode(state.Req, dns.RcodeNameError)
			m.Authoritative = true
			// m.Ns, _ = SOA(ctx, b, zone, state, opt)
			m.Ns, _ = soa_hack(pdb, zone, state)

			// state.W.WriteMsg(m)
			return 0, w.WriteMsg(m)
		}
	}

	return 0, w.WriteMsg(a)
}

func soa_hack(pdb PowerDNSGenericSQLBackend, zone string, state request.Request) ([]dns.RR, error) {
	minTtl := pdb.MinTtl(state)

	header := dns.RR_Header{Name: zone, Rrtype: dns.TypeSOA, Ttl: minTtl, Class: dns.ClassINET}

	Mbox := dnsutil.Join(hostmaster, zone)
	Ns := dnsutil.Join("ns.dns", zone)

	soa := &dns.SOA{Hdr: header,
		Mbox:    Mbox,
		Ns:      Ns,
		Serial:  pdb.Serial(state),
		Refresh: 7200,
		Retry:   1800,
		Expire:  86400,
		Minttl:  minTtl,
	}
	return []dns.RR{soa}, nil
}

func (pdb PowerDNSGenericSQLBackend) SearchWildcard(qname string, qtype uint16) (redords []*pdnsmodel.Record, err error) {
	// find domain, then find matched sub domain
	name := qname
	qnameNoDot := strings.ToLower(strings.TrimSuffix(qname, "."))
	typ := dns.TypeToString[qtype]
	name = qnameNoDot
NEXT_ZONE:
	if i := strings.IndexRune(name, '.'); i > 0 {
		name = name[i+1:]
	} else {
		return
	}
	var domain pdnsmodel.Domain

	if err := pdb.Limit(1).Find(&domain, "name = ?", name).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			goto NEXT_ZONE
		}
		return nil, err
	}

	if err := pdb.Find(&redords, "domain_id = ? and ( ? = 'ANY' or type = ? ) and name like '%*%'", domain.ID, typ, typ).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, nil
		}
		return nil, err
	}
	// filter
	var matched []*pdnsmodel.Record
	for _, v := range redords {
		if WildcardMatch(qnameNoDot, v.Name) {
			matched = append(matched, v)
		}
	}
	redords = matched
	return
}

func ParseSOA(rr *dns.SOA, line string) bool {
	splites := strings.Split(line, " ")
	if len(splites) < 7 {
		return false
	}
	rr.Ns = splites[0]
	rr.Mbox = splites[1]
	if i, err := strconv.Atoi(splites[2]); err != nil {
		return false
	} else {
		rr.Serial = uint32(i)
	}
	if i, err := strconv.Atoi(splites[3]); err != nil {
		return false
	} else {
		rr.Refresh = uint32(i)
	}
	if i, err := strconv.Atoi(splites[4]); err != nil {
		return false
	} else {
		rr.Retry = uint32(i)
	}
	if i, err := strconv.Atoi(splites[5]); err != nil {
		return false
	} else {
		rr.Expire = uint32(i)
	}
	if i, err := strconv.Atoi(splites[6]); err != nil {
		return false
	} else {
		rr.Minttl = uint32(i)
	}
	return true
}

// Dummy wildcard match
func WildcardMatch(s1, s2 string) bool {
	if s1 == "." || s2 == "." {
		return true
	}

	l1 := dns.SplitDomainName(s1)
	l2 := dns.SplitDomainName(s2)

	if len(l1) != len(l2) {
		return false
	}

	for i := range l1 {
		if !equal(l1[i], l2[i]) {
			return false
		}
	}

	return true
}

func equal(a, b string) bool {
	if b == "*" || a == "*" {
		return true
	}
	// might be lifted into API function.
	la := len(a)
	lb := len(b)
	if la != lb {
		return false
	}

	for i := la - 1; i >= 0; i-- {
		ai := a[i]
		bi := b[i]
		if ai >= 'A' && ai <= 'Z' {
			ai |= 'a' - 'A'
		}
		if bi >= 'A' && bi <= 'Z' {
			bi |= 'a' - 'A'
		}
		if ai != bi {
			return false
		}
	}
	return true
}
