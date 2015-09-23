package mpq

import (
	"encoding/binary"
	"strings"
)

var blockEncryptionTable []uint32
var bInitTable bool

func init() {
	GenerateEncryptionTable(0x500)
}

func GenerateEncryptionTable(tableSize int32) {
	blockEncryptionTable = make([]uint32, tableSize)

	var seed uint32 = 0x00100001

	for mainIdx := 0; mainIdx < 256; mainIdx++ {
		currentIdx := mainIdx

		for innerIdx := 0; innerIdx < 5; innerIdx++ {
			seed = (seed*125 + 3) % 0x2AAAAB
			temp1 := (seed & 0xFFFF) << 0x10

			seed = (seed*125 + 3) % 0x2AAAAB
			temp2 := (seed & 0xFFFF)

			blockEncryptionTable[currentIdx] = (temp1 | temp2)

			currentIdx += 0x100
		}
	}
}

func HashString(input string, offset uint16) (hash uint32) {
	var seed1 uint32 = 0x7FED7FED
	var seed2 uint32 = 0xEEEEEEEE

	str := strings.ToUpper(input)

	for _, curChar := range str {
		value := blockEncryptionTable[offset+uint16(curChar)]
		seed1 = (value ^ (seed1 + seed2)) & 0xFFFFFFFF
		seed2 = (uint32(curChar) + seed1 + seed2 + (seed2 << 5) + 3) & 0xFFFFFFFF
	}

	return seed1
}

func Decrypt(table *[]byte, seed1 uint32) {
	var seed2 uint32 = 0xEEEEEEEE

	size := len(*table)
	pos := 0
	for ; size >= 4; size -= 4 {
		seed2 += blockEncryptionTable[0x400+(seed1&0xFF)]
		curEntry := binary.LittleEndian.Uint32((*table)[pos : pos+4])
		entry := curEntry ^ (seed1 + seed2)
		seed1 = ((^seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B)
		seed2 = uint32(entry) + seed2 + (seed2 << 5) + 3

		binary.LittleEndian.PutUint32((*table)[pos:pos+4], entry)
		pos += 4
	}
	return
}

func Encrypt(table *[]byte, seed1 uint32) {
	var seed2 uint32 = 0xEEEEEEEE

	size := len(*table)
	pos := 0
	for ; size >= 4; size -= 4 {
		seed2 += blockEncryptionTable[0x400+(seed1&0xFF)]
		curEntry := binary.LittleEndian.Uint32((*table)[pos : pos+4])
		entry := curEntry ^ (seed1 + seed2)
		seed1 = ((^seed1 << 0x15) + 0x11111111) | (seed1 >> 0x0B)
		seed2 = uint32(curEntry) + seed2 + (seed2 << 5) + 3

		binary.LittleEndian.PutUint32((*table)[pos:pos+4], entry)
		pos += 4
	}
	return
}

func EncryptWithString(table *[]byte, key string) {
	seed := HashString(key, 0)
	Encrypt(table, seed)
}

func DecryptWithString(table *[]byte, key string) {
	seed := HashString(key, 0)
	Decrypt(table, seed)
}
