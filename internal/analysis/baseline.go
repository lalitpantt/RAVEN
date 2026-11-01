package analysis

import (
	"errors"
	"math"
	"sort"
)

const baselineAlgorithm = "rolling_median_mad_v1"

type BaselineAssessment struct {
	Ready          bool
	HistoryCount   int
	Observed       int64
	Median         float64
	MAD            float64
	LowerThreshold float64
	UpperThreshold float64
	Direction      string
}

// shortcut: this compares only recent equal-length intervals and ignores weekly seasonality; upgrade when labeled source traffic proves same-hour/week comparison is required.
// AssessRateBaseline uses the previous intervals' median and median absolute
// deviation. The one-count spread floor keeps zero-MAD histories usable.
func AssessRateBaseline(history []int64, observed int64, minimumHistory int, sensitivity float64) (BaselineAssessment, error) {
	if observed < 0 || len(history) > 28 || minimumHistory < 4 || minimumHistory > 28 || sensitivity < 2 || sensitivity > 6 || math.IsNaN(sensitivity) || math.IsInf(sensitivity, 0) {
		return BaselineAssessment{}, errors.New("invalid baseline inputs")
	}
	for _, count := range history {
		if count < 0 {
			return BaselineAssessment{}, errors.New("baseline history counts cannot be negative")
		}
	}
	result := BaselineAssessment{HistoryCount: len(history), Observed: observed}
	if len(history) < minimumHistory {
		return result, nil
	}
	ordered := append([]int64(nil), history...)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	median := medianCounts(ordered)
	deviations := make([]float64, len(ordered))
	for i, count := range ordered {
		deviations[i] = math.Abs(float64(count) - median)
	}
	sort.Float64s(deviations)
	mad := medianValues(deviations)
	spread := math.Max(1, 1.4826*mad)
	margin := sensitivity * spread
	result.Ready = true
	result.Median = median
	result.MAD = mad
	result.LowerThreshold = math.Max(0, median-margin)
	result.UpperThreshold = median + margin
	if float64(observed) > result.UpperThreshold {
		result.Direction = "high"
	} else if median > 0 && (float64(observed) < result.LowerThreshold || result.LowerThreshold == 0 && observed == 0) {
		result.Direction = "low"
	}
	return result, nil
}

func medianCounts(sorted []int64) float64 {
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return float64(sorted[middle])
	}
	return (float64(sorted[middle-1]) + float64(sorted[middle])) / 2
}

func medianValues(sorted []float64) float64 {
	middle := len(sorted) / 2
	if len(sorted)%2 == 1 {
		return sorted[middle]
	}
	return (sorted[middle-1] + sorted[middle]) / 2
}
