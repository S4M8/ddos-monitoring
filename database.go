package main

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

// InitDB initializes the SQLite database
func InitDB(dataSourceName string) {
	var err error
	db, err = sql.Open("sqlite3", dataSourceName)
	if err != nil {
		log.Fatalf("Failed to open database: %v", err)
	}

	createTableSQL := `
	CREATE TABLE IF NOT EXISTS ip_stats (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL UNIQUE,
		packet_count INTEGER,
		byte_count INTEGER,
		last_seen DATETIME,
		suspicious_flag BOOLEAN
	);

	CREATE TABLE IF NOT EXISTS suspicious_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip_address TEXT NOT NULL,
		event_time DATETIME NOT NULL,
		event_type TEXT NOT NULL,
		details TEXT
	);
	`

	_, err = db.Exec(createTableSQL)
	if err != nil {
		log.Fatalf("Failed to create tables: %v", err)
	}
	log.Println("Database initialized successfully")
}

// SaveIPStats saves or updates IP statistics in the database
func SaveIPStats(ip string, stats *IPStats) {
	_, err := db.Exec(`
	INSERT INTO ip_stats (ip_address, packet_count, byte_count, last_seen, suspicious_flag)
	VALUES (?, ?, ?, ?, ?)
	ON CONFLICT(ip_address) DO UPDATE SET
		packet_count = excluded.packet_count,
		byte_count = excluded.byte_count,
		last_seen = excluded.last_seen,
		suspicious_flag = excluded.suspicious_flag
	`, ip, stats.PacketCount, stats.ByteCount, stats.LastSeen, stats.SuspiciousFlag)
	if err != nil {
		log.Printf("Error saving IP stats for %s: %v", ip, err)
	}
}

// LogSuspiciousEvent logs a suspicious event to the database
func LogSuspiciousEvent(ip, eventType, details string) {
	_, err := db.Exec(`
	INSERT INTO suspicious_events (ip_address, event_time, event_type, details)
	VALUES (?, ?, ?, ?)
	`, ip, time.Now(), eventType, details)
	if err != nil {
		log.Printf("Error logging suspicious event for %s: %v", ip, err)
	}
}
