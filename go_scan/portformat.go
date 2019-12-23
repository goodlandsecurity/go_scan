package go_scan

import (
	"errors"
	"strconv"
	"strings"
)

const (
	portErrMsg = "Invalid port specification"
)

func dashSplit(sp string, ports *[]int) error {
	dp := strings.Split(sp, "-")
	if len(dp) != 2 {
		return errors.New(portErrMsg)
	}
	start, err := strconv.Atoi(dp[0])
	if err != nil {
		return errors.New(portErrMsg)
	}
	end, err := strconv.Atoi(dp[1])
	if err != nil {
		return errors.New(portErrMsg)
	}
	if start > end || start < 1 || end > 65535 {
		return errors.New(portErrMsg)
	}
	for ; start <= end; start++ {
		*ports = append(*ports, start)
	}
	return nil
}

func convertAndAddPort(p string, ports *[]int) error {
	i, err := strconv.Atoi(p)
	if err != nil {
		return errors.New(portErrMsg)
	}
	if i < 1 || i > 65535 {
		return errors.New(portErrMsg)
	}
	*ports = append(*ports, i)
	return nil
}

// Parse turns a string of ports separated by '-' or ',' and returns a slice of integers
func Parse(s string) ([]int, error) {
	ports := []int{}
	if strings.Contains(s, ",") && strings.Contains(s, "-"){
		sp := strings.Split(s, ",")
		for _, p := range sp {
			if strings.Contains(p, "-") {
				if err := dashSplit(p, &ports); err != nil {
					return ports, err
				}
			} else {
				if err := convertAndAddPort(p, &ports); err != nil {
					return ports, err
				}
			}
		}
	} else if strings.Contains(s, ",") {
		sp := strings.Split(s, ",")
		for _, p := range sp {
			convertAndAddPort(p, &ports)
		}
	} else if strings.Contains(s, "-") {
		if err := dashSplit(s, &ports); err != nil {
			return ports, err
		}
	} else {
		if err := convertAndAddPort(s, &ports); err != nil {
			return ports, err
		}
	}
	return ports, nil
}
