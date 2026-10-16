//go:build !race

package notify

// raceDetectorEnabled is the counterpart of the value in race_test.go. See there
// for what reads it and why.
const raceDetectorEnabled = false
