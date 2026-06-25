package protocol

import (
	"bytes"
	"fmt"
	"strings"
	"time"
)

// DBEvent 完整数据库事件
type DBEvent struct {
	Timestamp     int64  `json:"timestamp"`
	PID           uint32 `json:"pid"`
	SrcIP         string `json:"src_ip"`
	DstIP         string `json:"dst_ip"`
	SrcPort       uint16 `json:"src_port"`
	DstPort       uint16 `json:"dst_port"`
	DBType        string `json:"db_type"`    // mysql / redis
	Query         string `json:"query"`      // SQL语句或Redis命令
	Command       string `json:"command"`    // 命令类型
	AffectedRows  int64  `json:"affected_rows"`
	ErrorCode     int    `json:"error_code"`
	ErrorMsg      string `json:"error_msg"`
	LatencyMs     int64  `json:"latency_ms"`
	IsSlow        bool   `json:"is_slow"`    // >100ms
	IsDangerous   bool   `json:"is_dangerous"` // DROP/TRUNCATE/DELETE无WHERE
	Direction     uint8  `json:"direction"`  // 0=请求 1=响应
}

// MySQL Command Types
const (
	MySQLCmdSleep         = 0x00
	MySQLCmdQuit          = 0x01
	MySQLCmdInitDB        = 0x02
	MySQLCmdQuery         = 0x03
	MySQLCmdFieldList     = 0x04
	MySQLCmdCreateDB      = 0x05
	MySQLCmdDropDB        = 0x06
	MySQLCmdRefresh       = 0x07
	MySQLCmdShutdown      = 0x08
	MySQLCmdStatistics    = 0x09
	MySQLCmdProcessInfo   = 0x0a
	MySQLCmdConnect       = 0x0b
	MySQLCmdProcessKill   = 0x0c
	MySQLCmdDebug         = 0x0d
	MySQLCmdPing          = 0x0e
	MySQLCmdTime          = 0x0f
	MySQLCmdDelayedInsert = 0x10
	MySQLCmdChangeUser    = 0x11
	MySQLCmdBinlogDump    = 0x12
	MySQLCmdTableDump     = 0x13
	MySQLCmdConnectOut    = 0x14
	MySQLCmdRegisterSlave = 0x15
	MySQLCmdStmtPrepare   = 0x16
	MySQLCmdStmtExecute   = 0x17
	MySQLCmdStmtSendLongData = 0x18
	MySQLCmdStmtClose     = 0x19
	MySQLCmdStmtReset     = 0x1a
	MySQLCmdSetOption     = 0x1b
	MySQLCmdStmtFetch     = 0x1c
)

var mysqlCmdNames = map[byte]string{
	0x00: "Sleep", 0x01: "Quit", 0x02: "InitDB", 0x03: "Query",
	0x04: "FieldList", 0x05: "CreateDB", 0x06: "DropDB", 0x07: "Refresh",
	0x08: "Shutdown", 0x09: "Statistics", 0x0a: "ProcessInfo", 0x0b: "Connect",
	0x0c: "ProcessKill", 0x0d: "Debug", 0x0e: "Ping", 0x0f: "Time",
	0x10: "DelayedInsert", 0x11: "ChangeUser", 0x12: "BinlogDump", 0x13: "TableDump",
	0x14: "ConnectOut", 0x15: "RegisterSlave", 0x16: "StmtPrepare", 0x17: "StmtExecute",
	0x18: "StmtSendLongData", 0x19: "StmtClose", 0x1a: "StmtReset", 0x1b: "SetOption",
	0x1c: "StmtFetch",
}

// MySQL Response Packet Types
const (
	MySQLResponseOK  = 0x00
	MySQLResponseEOF = 0xFE
	MySQLResponseERR = 0xFF
)

// ParseMySQLPacket 解析完整MySQL协议包
func ParseMySQLPacket(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *DBEvent {
	if len(payload) < 5 {
		return nil
	}
	rec := &DBEvent{
		Timestamp: time.Now().UnixMilli(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		DBType:    "mysql",
		Direction: direction,
	}
	if direction == 1 {
		rec.SrcIP, rec.DstIP = rec.DstIP, rec.SrcIP
		rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
	}

	// MySQL packet header: 3 bytes length + 1 byte sequence
	pktLen := int(payload[0]) | int(payload[1])<<8 | int(payload[2])<<16
	seqID := payload[3]
	_ = seqID
	if pktLen == 0 || pktLen > len(payload)-4 {
		return nil
	}
	body := payload[4 : 4+pktLen]
	if len(body) < 1 {
		return nil
	}

	if direction == 1 { // request
		cmdType := body[0]
		rec.Command = mysqlCmdName(cmdType)
		switch cmdType {
		case MySQLCmdQuery:
			if len(body) > 1 {
				rec.Query = string(body[1:])
				rec.Query = sanitizeSQL(rec.Query)
				rec.IsDangerous = detectDangerousSQL(rec.Query)
			}
		case MySQLCmdStmtPrepare:
			if len(body) > 1 {
				rec.Query = "Prepare: " + sanitizeSQL(string(body[1:]))
			}
		case MySQLCmdInitDB:
			if len(body) > 1 {
				rec.Query = "USE " + string(body[1:])
			}
		case MySQLCmdFieldList:
			if len(body) > 1 {
				rec.Query = "FieldList: " + string(body[1:])
			}
		default:
			rec.Query = fmt.Sprintf("Cmd(%s)", rec.Command)
		}
	} else { // response
		status := body[0]
		switch status {
		case MySQLResponseOK:
			rec.ErrorCode = 0
			if len(body) > 1 {
				// Parse affected rows (length encoded integer)
				_, affected, _ := parseLengthEncodedInt(body, 1)
				rec.AffectedRows = affected
			}
		case MySQLResponseERR:
			if len(body) >= 3 {
				rec.ErrorCode = int(body[1]) | int(body[2])<<8
			}
			if len(body) > 3 {
				rec.ErrorMsg = string(body[3:])
			}
		case MySQLResponseEOF:
			rec.ErrorCode = 0
			// EOF packet, no error
		default:
			// Result set header
			rec.ErrorCode = 0
		}
	}
	return rec
}

func mysqlCmdName(cmd byte) string {
	if name, ok := mysqlCmdNames[cmd]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02x)", cmd)
}

// parseLengthEncodedInt 解析MySQL长度编码整数
func parseLengthEncodedInt(data []byte, offset int) (newOffset int, value int64, ok bool) {
	if offset >= len(data) {
		return offset, 0, false
	}
	switch data[offset] {
	case 0xFB:
		return offset + 1, 0, true // NULL
	case 0xFC:
		if offset+3 > len(data) {
			return offset, 0, false
		}
		return offset + 3, int64(data[offset+1]) | int64(data[offset+2])<<8, true
	case 0xFD:
		if offset+4 > len(data) {
			return offset, 0, false
		}
		return offset + 4, int64(data[offset+1]) | int64(data[offset+2])<<8 | int64(data[offset+3])<<16, true
	case 0xFE:
		if offset+9 > len(data) {
			return offset, 0, false
		}
		return offset + 9, int64(data[offset+1]) | int64(data[offset+2])<<8 | int64(data[offset+3])<<16 |
			int64(data[offset+4])<<24 | int64(data[offset+5])<<32 | int64(data[offset+6])<<40 |
			int64(data[offset+7])<<48 | int64(data[offset+8])<<56, true
	default:
		return offset + 1, int64(data[offset]), true
	}
}

// detectDangerousSQL 检测危险SQL操作
func detectDangerousSQL(sql string) bool {
	upper := strings.ToUpper(sql)
	// DROP / TRUNCATE
	if strings.Contains(upper, "DROP ") || strings.Contains(upper, "TRUNCATE ") {
		return true
	}
	// DELETE without WHERE
	if strings.Contains(upper, "DELETE ") && !strings.Contains(upper, "WHERE ") {
		return true
	}
	// UPDATE without WHERE
	if strings.Contains(upper, "UPDATE ") && !strings.Contains(upper, "WHERE ") {
		return true
	}
	return false
}

// ParseRedisPacket 解析Redis RESP协议
func ParseRedisPacket(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *DBEvent {
	if len(payload) < 1 {
		return nil
	}
	rec := &DBEvent{
		Timestamp: time.Now().UnixMilli(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		DBType:    "redis",
		Direction: direction,
	}
	if direction == 1 {
		rec.SrcIP, rec.DstIP = rec.DstIP, rec.SrcIP
		rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
	}

	// RESP protocol parsing
	switch payload[0] {
	case '*': // Array (request)
		parts := bytes.Split(payload, []byte("\r\n"))
		if len(parts) >= 3 {
			rec.Command = strings.ToUpper(strings.TrimSpace(string(parts[2])))
			// Build full command with args
			var cmdParts []string
			for i := 2; i < len(parts); i += 2 {
				if len(parts[i]) > 0 {
					cmdParts = append(cmdParts, strings.TrimSpace(string(parts[i])))
				}
			}
			rec.Query = strings.Join(cmdParts, " ")
			rec.IsDangerous = detectDangerousRedis(rec.Command, rec.Query)
		}
	case '+': // Simple String
		rec.Query = "OK"
		rec.ErrorCode = 0
	case '-': // Error
		rec.Query = string(payload[1:])
		rec.ErrorCode = 1
	case ':': // Integer
		rec.Query = string(payload[1:])
		rec.ErrorCode = 0
		fmt.Sscanf(rec.Query, "%d", &rec.AffectedRows)
	case '$': // Bulk String
		rec.Query = "BulkString"
	default:
		rec.Query = string(payload[:min(50, len(payload))])
	}
	return rec
}

// detectDangerousRedis 检测危险Redis命令
func detectDangerousRedis(cmd, query string) bool {
	upper := strings.ToUpper(cmd)
	dangerous := []string{"FLUSHALL", "FLUSHDB", "SHUTDOWN", "DEBUG", "CONFIG", "SAVE", "BGREWRITEAOF"}
	for _, d := range dangerous {
		if upper == d || strings.HasPrefix(upper, d+" ") {
			return true
		}
	}
	return false
}

func sanitizeSQL(sql string) string {
	if len(sql) > 200 {
		sql = sql[:200] + "..."
	}
	return sql
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// DBRecord 向后兼容
type DBRecord struct {
	Timestamp   time.Time
	ProbeID     string
	SrcIP       string
	DstIP       string
	SrcPort     uint16
	DstPort     uint16
	DBType      string
	Query       string
	LatencyMs   float64
	IsSlow      bool
	ErrorCode   int
	ErrorMsg    string
}

// ParseMySQL 向后兼容旧接口
func ParseMySQL(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *DBRecord {
	if len(payload) < 5 {
		return nil
	}
	rec := &DBRecord{
		Timestamp: time.Now(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		DBType: "mysql",
	}
	if direction == 1 {
		rec.SrcIP, rec.DstIP = rec.DstIP, rec.SrcIP
		rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
	}
	cmdType := payload[4]
	switch cmdType {
	case 0x03:
		rec.Query = string(payload[5:])
	case 0x16:
		rec.Query = "Prepare"
	case 0x17:
		rec.Query = "Execute"
	case 0x1e:
		rec.Query = "Binlog Dump"
	default:
		rec.Query = fmt.Sprintf("Cmd(0x%02x)", cmdType)
	}
	rec.Query = sanitizeSQL(rec.Query)
	rec.IsSlow = false
	return rec
}

// ParseRedis 向后兼容旧接口
func ParseRedis(payload []byte, srcIP, dstIP string, srcPort, dstPort uint16, direction uint8) *DBRecord {
	if len(payload) < 1 {
		return nil
	}
	rec := &DBRecord{
		Timestamp: time.Now(),
		SrcIP:     srcIP, DstIP: dstIP,
		SrcPort: srcPort, DstPort: dstPort,
		DBType: "redis",
	}
	if direction == 1 {
		rec.SrcIP, rec.DstIP = rec.DstIP, rec.SrcIP
		rec.SrcPort, rec.DstPort = rec.DstPort, rec.SrcPort
	}
	if payload[0] == '*' {
		parts := bytes.Split(payload, []byte("\r\n"))
		if len(parts) >= 3 {
			rec.Query = strings.TrimSpace(string(parts[2]))
		}
	} else if payload[0] == '+' || payload[0] == '-' || payload[0] == ':' || payload[0] == '$' {
		rec.Query = "Response"
	} else {
		rec.Query = string(payload[:min(50, len(payload))])
	}
	return rec
}

// BuildDBEvent 构建完整DB事件（请求+响应）
func BuildDBEvent(req, resp *DBEvent) *DBEvent {
	if req == nil || resp == nil {
		return nil
	}
	return &DBEvent{
		Timestamp:    req.Timestamp,
		PID:          req.PID,
		SrcIP:        req.SrcIP,
		DstIP:        req.DstIP,
		SrcPort:      req.SrcPort,
		DstPort:      req.DstPort,
		DBType:       req.DBType,
		Query:        req.Query,
		Command:      req.Command,
		AffectedRows: resp.AffectedRows,
		ErrorCode:    resp.ErrorCode,
		ErrorMsg:     resp.ErrorMsg,
		LatencyMs:    resp.LatencyMs,
		IsSlow:       resp.LatencyMs > 100,
		IsDangerous:  req.IsDangerous,
		Direction:    1,
	}
}
