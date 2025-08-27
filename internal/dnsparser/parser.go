package dnsparser

import (
	"fmt"
	"github.com/faanross/legehniss_C2/internal/config"
	"github.com/miekg/dns"
	"log"
	"time"
)

// DNSParser handles DNS packet parsing and analysis
type DNSParser struct {
	Config *config.DNSServerConfig
}

// NewDNSParser creates a new DNS packet parser
func NewDNSParser(config *config.DNSServerConfig) *DNSParser {
	return &DNSParser{
		Config: config,
	}
}

// ParsePacket performs complete DNS packet analysis (highest-level)
func (p *DNSParser) ParsePacket(rawData []byte, clientAddr string) *ParsedPacket {
	result := &ParsedPacket{
		RawData:    rawData,
		Size:       len(rawData),
		ReceivedAt: time.Now(),
		ClientAddr: clientAddr,
	}

	// Step 1: Parse with miekg/dns library
	msg := new(dns.Msg)

	// Unpack() takes []byte -> dns.Msg
	err := msg.Unpack(rawData)
	if err != nil {
		result.Valid = false
		result.Error = fmt.Errorf("DNS packet parsing failed: %w", err)
		result.Analysis = &PacketAnalysis{
			PacketType:   "MALFORMED",
			IsWellFormed: false,
			Issues:       []string{err.Error()},
		}
		return result
	}

	result.Message = msg
	result.Valid = true

	// Step 2: Analyze header (+ does basic analysis on type, "normalcy" etc.)
	result.Header = p.analyzeHeader(msg)

	// log header analysis
	logAnalyzeHeader(result.Header)

	// Step 3: Analyze question
	if len(msg.Question) > 0 {
		result.Question = p.analyzeQuestion(msg.Question[0])
		// log question analysis
		logAnalyzeQuestion(result.Question)
	}

	// Step 4: Perform high-level analysis
	result.Analysis = p.analyzePacket(msg, result.Header, result.Question)
	logAnalyzePacket(result.Analysis)

	return result
}

// analyzeHeader provides detailed header analysis
func (p *DNSParser) analyzeHeader(msg *dns.Msg) *HeaderAnalysis {

	// these values all have library objects in miekg/dns (all except z)
	analysis := &HeaderAnalysis{
		ID:              msg.Id,
		QR:              msg.Response,
		Opcode:          msg.Opcode,
		AA:              msg.Authoritative,
		TC:              msg.Truncated,
		RD:              msg.RecursionDesired,
		RA:              msg.RecursionAvailable,
		Rcode:           msg.Rcode,
		QuestionCount:   uint16(len(msg.Question)),
		AnswerCount:     uint16(len(msg.Answer)),
		AuthorityCount:  uint16(len(msg.Ns)),
		AdditionalCount: uint16(len(msg.Extra)),
	}

	// Extract Z flag from raw header since miekg/dns doesn't expose it
	if len(p.getRawHeader()) >= 4 {
		// Z flag is bits 4-6 of the flags field
		flags := uint16(p.getRawHeader()[2])<<8 | uint16(p.getRawHeader()[3])
		analysis.Z = uint8((flags >> 4) & 0x07)
	}

	// String representations
	analysis.QRString = p.qrToString(analysis.QR)
	analysis.OpcodeString = p.opcodeToString(analysis.Opcode)
	analysis.RcodeString = p.rcodeToString(analysis.Rcode)

	// Analysis flags
	analysis.IsQuery = !analysis.QR
	analysis.IsResponse = analysis.QR
	analysis.IsStandardQuery = analysis.Opcode == dns.OpcodeQuery
	analysis.HasNonZeroZ = analysis.Z != 0
	analysis.IsRecursionDesired = analysis.RD

	return analysis
}

func logAnalyzeHeader(header *HeaderAnalysis) {

	// NOTE I HAVE NOT YET IMPLEMENTED LOGGER SO UNCOMMENTING THIS FOR NOW

	log.Printf("DNS Packet Header Values\nid=%v\nqr=%v\nopcode=%v\naa=%v\ntc=%v\nrd=%v\nra=%v\nz=%v\nrcode=%v\nquestion_count=%v\nanswer_count=%v\nauthority_count=%v\nadditional_count=%v",
		header.ID, header.QRString, header.OpcodeString, header.AA, header.TC, header.RD, header.RA, header.Z, header.RcodeString, header.QuestionCount, header.AnswerCount, header.AuthorityCount, header.AdditionalCount)

	//logging.Debug("DNS Packet Header Values",
	//	"id", header.ID,
	//	"qr", header.QRString,
	//	"opcode", header.OpcodeString,
	//	"aa", header.AA,
	//	"tc", header.TC,
	//	"rd", header.RD,
	//	"ra", header.RA,
	//	"z", header.Z,
	//	"rcode", header.RcodeString,
	//	"question_count", header.QuestionCount,
	//	"answer_count", header.AnswerCount,
	//	"authority_count", header.AuthorityCount,
	//	"additional_count", header.AdditionalCount,
	//)

	log.Printf("DNS Packet Header Analysis\nis_query=%v\nis_response=%v\nis_standard_query=%v\nhas_non_zero_z=%v\nis_recursion_desired=%v",
		header.IsQuery, header.IsResponse, header.IsStandardQuery, header.HasNonZeroZ, header.IsRecursionDesired)

	//logging.Info("DNS Packet Header Analysis",
	//	"is_query", header.IsQuery,
	//	"is_response", header.IsResponse,
	//	"is_standard_query", header.IsStandardQuery,
	//	"has_non_zero_z", header.HasNonZeroZ,
	//	"is_recursion_desired", header.IsRecursionDesired,
	//)

}

// analyzeQuestion provides detailed question analysis
func (p *DNSParser) analyzeQuestion(q dns.Question) *QuestionAnalysis {
	analysis := &QuestionAnalysis{
		Name:         q.Name,
		Qtype:        q.Qtype,
		QtypeString:  dns.TypeToString[q.Qtype],
		Qclass:       q.Qclass,
		QclassString: dns.ClassToString[q.Qclass],
	}

	// Domain analysis
	analysis.IsValidDomain = p.isValidDomainName(analysis.Name)
	analysis.IsFQDN = dns.IsFqdn(analysis.Name)
	analysis.DomainLabels = dns.SplitDomainName(analysis.Name)
	analysis.IsWildcard = len(analysis.DomainLabels) > 0 && analysis.DomainLabels[0] == "*"

	if analysis.Qclass == 1 {
		analysis.IsQClassInt = true
	} else {
		analysis.IsQClassInt = false
	}

	return analysis
}

func logAnalyzeQuestion(question *QuestionAnalysis) {

	log.Printf("DNS Packet Question Values\nname=%v\nqtype=%v\nqtype_string=%v\nqclass=%v\nqclass_string=%v", question.Name, question.Qtype, question.QtypeString, question.Qclass, question.QclassString)

	//logging.Debug("DNS Packet Question Values",
	//	"name", question.Name,
	//	"qtype", question.Qtype,
	//	"qtype_string", question.QtypeString,
	//	"qclass", question.Qclass,
	//	"qclass_string", question.QclassString,
	//)

	log.Printf("DNS Packet Question Analysis\nis_valid_domain=%v\nis_fqdn=%v\ndomain_labels=%v\nis_wild_card=%v\nis_qclass_int=%v", question.IsValidDomain, question.IsFQDN, question.DomainLabels, question.IsWildcard, question.IsQClassInt)

	//logging.Info("DNS Packet Question Analysis",
	//	"is_valid_domain", question.IsValidDomain,
	//	"is_fqdn", question.IsFQDN,
	//	"domain_labels", question.DomainLabels,
	//	"is_wild_card", question.IsWildcard,
	//	"is_qclass_int", question.IsQClassInt,
	//)

}

// analyzePacket performs high-level packet analysis
func (p *DNSParser) analyzePacket(msg *dns.Msg, header *HeaderAnalysis, question *QuestionAnalysis) *PacketAnalysis {
	analysis := &PacketAnalysis{
		IsWellFormed: true,
		IsStandard:   true,
		Issues:       []string{},
		Warnings:     []string{},
	}

	// Determine packet type
	if header.IsQuery {
		if header.IsStandardQuery {
			analysis.PacketType = "STANDARD_QUERY"
		} else {
			analysis.PacketType = fmt.Sprintf("QUERY_OPCODE_%d", header.Opcode)
		}
	} else {
		analysis.PacketType = "RESPONSE"
	}

	// Check for standard compliance issues
	if header.HasNonZeroZ {
		analysis.IsStandard = false
		analysis.Warnings = append(analysis.Warnings,
			fmt.Sprintf("Non-zero Z flag: %d (RFC 1035 requires 0)", header.Z))
	}

	if header.IsQuery && header.RA {
		analysis.Warnings = append(analysis.Warnings,
			"RA flag set in query (should only be set by servers)")
	}

	if header.IsQuery && header.AA {
		analysis.Warnings = append(analysis.Warnings,
			"AA flag set in query (should only be set in authoritative responses)")
	}

	// Check EDNS support
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype == dns.TypeOPT {
			analysis.HasEdns = true
			break
		}
	}

	// Check if server supports this query
	if question != nil {
		zone := p.Config.FindZone(question.Name)
		analysis.SupportedByServer = zone != nil

		if !analysis.SupportedByServer {
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("Server is not authoritative for domain: %s", question.Name))
		}

		// Check query type support
		if !p.isSupportedQueryType(question.Qtype) {
			analysis.Issues = append(analysis.Issues,
				fmt.Sprintf("Unsupported query type: %s", question.QtypeString))
		}
	}

	return analysis
}

func logAnalyzePacket(analysis *PacketAnalysis) {

	log.Printf("DNS High-Level Packet Analysis\npacket_type=%v\nis_well_formed=%v\nis_standard=%v\nhad_edns=%v\nsupported_by_server=%v\nissues=%v\nwarnings=%v", analysis.PacketType, analysis.IsWellFormed, analysis.IsStandard, analysis.HasEdns, analysis.SupportedByServer, analysis.Issues, analysis.Warnings)
	
	//logging.Debug("DNS High-Level Packet Analysis",
	//	"packet_type", analysis.PacketType,
	//	"is_well_formed", analysis.IsWellFormed,
	//	"is_standard", analysis.IsStandard,
	//	"had_edns", analysis.HasEdns,
	//	"supported_by_server", analysis.SupportedByServer,
	//	"issues", analysis.Issues,
	//	"warnings", analysis.Warnings,
	//)
}
