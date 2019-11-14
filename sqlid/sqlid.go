package sqlid

import (
	"crypto/md5"
	"encoding/hex"
	"log"
	"math"
	"os"
	"strconv"
	"strings"
)

func getMD5Hash(text string) string {
	hasher := md5.New()
	hasher.Write([]byte(text))
	return hex.EncodeToString(hasher.Sum(nil))
}

func toFixed(num float64, precision int) float64 {
	output := math.Pow(10, float64(precision))
	return float64(math.Round(num*output)) / output
}

//Get reutrns SQLid string for provided SQL Text
func Get(sql string) string {
	sql = strings.Trim(sql, "\x00") + "\x00"
	md5 := getMD5Hash(sql) /* get md5 hash */
	low16 := md5[16:]      /* we only need lower 16 */
	lq3 := low16[:8]       /* 3rd quarter (8 hex characters) */
	lq4 := low16[8:16]     /* 4th quarter (8 hex characters) */
	/* need to reverse order of each of the 4 pairs of hex characters */
	loq3 := lq3[6:8] + lq3[4:6] + lq3[2:4] + lq3[0:2]
	loq4 := lq4[6:8] + lq4[4:6] + lq4[2:4] + lq4[0:2]
	/* assembly back lower 16 after reversing order on each quarter */
	low16m := loq3 + loq4
	/* convert to number */
	lnumber, err := strconv.ParseUint(low16m, 16, 64)
	if err != nil {
		// handle error
		log.Println(err)
		os.Exit(2)
	}
	/* 13 pieces base-32 (5 bits each) make 65 bits. we do have 64 bits */
	lsqlid := ""
	const base32 = "0123456789abcdfghjkmnpqrstuvwxyz"
	for i := 1; i < 14; i++ {
		lidx := toFixed(float64(lnumber/uint64(math.Pow(32, float64(13-i)))), 0) /* index on BASE_32 */
		lsqlid = lsqlid + base32[int(lidx):int(lidx)+1]                          /* stitch 13 characters */
		lnumber = lnumber - uint64(lidx)*uint64(math.Pow(32, float64(13-i)))     /* for next piece */
	}
	return lsqlid
}