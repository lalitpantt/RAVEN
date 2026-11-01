package analysis

import (
	"encoding/json"
	"os"
	"testing"
)

func TestAssessRateBaselineLabeledFixture(t *testing.T) {
	data, err := os.ReadFile("../../analysis/examples/baselines/rate-series.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Algorithm           string  `json:"algorithm"`
		MinimumHistory      int     `json:"minimum_history"`
		Sensitivity         float64 `json:"sensitivity"`
		FixedUpperThreshold int64   `json:"fixed_upper_threshold"`
		ExpectedMetrics     struct {
			RollingFalsePositives int `json:"rolling_false_positives"`
			RollingMissed         int `json:"rolling_missed"`
			FixedFalsePositives   int `json:"fixed_false_positives"`
			FixedMissed           int `json:"fixed_missed"`
		} `json:"expected_metrics"`
		Cases []struct {
			Label              string  `json:"label"`
			History            []int64 `json:"history"`
			Observed           int64   `json:"observed"`
			Expected           string  `json:"expected"`
			KnownFalsePositive bool    `json:"known_false_positive"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Algorithm != baselineAlgorithm || len(fixture.Cases) == 0 {
		t.Fatalf("invalid baseline fixture: %+v", fixture)
	}
	baselineFalsePositives, baselineMissed, staticFalsePositives, staticMissed := 0, 0, 0, 0
	for _, test := range fixture.Cases {
		t.Run(test.Label, func(t *testing.T) {
			got, err := AssessRateBaseline(test.History, test.Observed, fixture.MinimumHistory, fixture.Sensitivity)
			if err != nil {
				t.Fatal(err)
			}
			if test.KnownFalsePositive {
				if got.Direction == "" {
					t.Fatalf("fixture did not expose expected seasonality false positive: %+v", got)
				}
				baselineFalsePositives++
			} else if got.Direction != test.Expected {
				if test.Expected == "" {
					baselineFalsePositives++
				} else {
					baselineMissed++
				}
			}
			staticDirection := ""
			if test.Observed > fixture.FixedUpperThreshold {
				staticDirection = "high"
			}
			if staticDirection != test.Expected {
				if staticDirection == "" {
					staticMissed++
				} else {
					staticFalsePositives++
				}
			}
		})
	}
	if baselineFalsePositives != fixture.ExpectedMetrics.RollingFalsePositives || baselineMissed != fixture.ExpectedMetrics.RollingMissed || staticFalsePositives != fixture.ExpectedMetrics.FixedFalsePositives || staticMissed != fixture.ExpectedMetrics.FixedMissed {
		t.Fatalf("synthetic fixture metrics: rolling FP=%d missed=%d; fixed FP=%d missed=%d", baselineFalsePositives, baselineMissed, staticFalsePositives, staticMissed)
	}
}

func TestAssessRateBaselineRequiresHistoryAndValidInputs(t *testing.T) {
	warming, err := AssessRateBaseline([]int64{2, 2, 2}, 20, 4, 3)
	if err != nil || warming.Ready || warming.HistoryCount != 3 {
		t.Fatalf("warm-up result=%+v err=%v", warming, err)
	}
	for _, test := range []struct {
		history     []int64
		observed    int64
		minimum     int
		sensitivity float64
	}{
		{[]int64{1, 1, -1, 1}, 1, 4, 3}, {[]int64{1, 1, 1, 1}, -1, 4, 3}, {[]int64{1, 1, 1, 1}, 1, 3, 3}, {[]int64{1, 1, 1, 1}, 1, 4, 7},
	} {
		if _, err := AssessRateBaseline(test.history, test.observed, test.minimum, test.sensitivity); err == nil {
			t.Fatalf("invalid inputs accepted: %+v", test)
		}
	}
}
