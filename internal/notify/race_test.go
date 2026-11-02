//go:build race

package notify

// raceDetectorEnabled reports whether the test binary was built with -race.
//
// Used by TestHubSignal_SlowSubscriber_ReceiveIsOrderedAfterTheLatestPublish,
// which asserts a happens-before edge: without the detector an unsynchronised
// read just returns a value and the test cannot fail, so it skips instead of
// passing for the wrong reason.
const raceDetectorEnabled = true
