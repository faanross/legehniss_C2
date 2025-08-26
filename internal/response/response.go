package response

import (
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/miekg/dns"
	"math/rand"
	"time"
)

// BuildDNSResponse takes the parsed response data and translates it into a dns.Msg object.
func BuildDNSResponse(resp config.DNSResponse) (*dns.Msg, error) {

	msg := new(dns.Msg)

	// Header.ID is taken from YAML, OR, if set to 0, we'll generate it randomly

	r := rand.New(rand.NewSource(time.Now().UnixNano()))

	if resp.Header.ID == 0 {
		msg.Id = uint16(r.Intn(65536))
	} else {
		msg.Id = resp.Header.ID
	}

	// For the following 3 fields we first want to use our maps in package models
	// To convert their struct field values to those found in miekg package

	opCode, ok := config.OpCodeMap[resp.Header.OpCode]
	if !ok {
		return nil, fmt.Errorf("invalid opcode: %s", resp.Header.OpCode)
	}
	msg.Opcode = opCode

	qType, ok := config.QTypeMap[resp.Question.Type]
	if !ok {
		return nil, fmt.Errorf("invalid question type: %s", resp.Question.Type)
	}

	qClass, ok := config.QClassMap[resp.Question.Class]
	if !ok {
		return nil, fmt.Errorf("invalid question class: %s", resp.Question.Class)
	}

	// For all the remaining fields we can directly use the struct field values

	msg.Response = resp.Header.QR

	msg.Authoritative = resp.Header.Authoritative
	msg.Truncated = resp.Header.Truncated
	msg.RecursionDesired = resp.Header.RecursionDesired
	msg.RecursionAvailable = resp.Header.RecursionAvailable

	msg.Rcode = int(resp.Header.RCode)

	// Reminder: Z-Value cannot be created using miekg/dns,
	// We'll do it manually using ApplyManualOverrides()

	// Manually create the Question struct and append it to the message.
	// This gives us full control and avoids the problematic SetQuestion helper.
	msg.Question = []dns.Question{
		{
			Name:   dns.Fqdn(resp.Question.Name),
			Qtype:  qType,
			Qclass: qClass,
		},
	}

	// Add answer records if this is a response
	if resp.Header.QR {
		for _, answer := range resp.Answers {
			switch answer.Type {
			case "TXT":
				rr := &dns.TXT{
					Hdr: dns.RR_Header{
						Name:   dns.Fqdn(answer.Name),
						Rrtype: dns.TypeTXT,
						Class:  dns.ClassINET,
						Ttl:    answer.TTL,
					},
					Txt: []string{answer.Data},
				}
				msg.Answer = append(msg.Answer, rr)
				// Add other record types as needed
			}
		}
	}
	return msg, nil
}
