package pdf

import (
	"math"
	"testing"
)

func TestGetIntRejectsOutOfRangeFloat(t *testing.T) {
	d := Dict{"K": float64(1e20)}
	if v, ok := d.GetInt("K"); ok {
		t.Errorf("GetInt should refuse float64 out of int range, got (%d, true)", v)
	}
}

func TestGetIntRejectsNaN(t *testing.T) {
	d := Dict{"K": math.NaN()}
	if _, ok := d.GetInt("K"); ok {
		t.Error("GetInt should refuse NaN")
	}
}

func TestGetIntRejectsInf(t *testing.T) {
	d := Dict{"K": math.Inf(1)}
	if _, ok := d.GetInt("K"); ok {
		t.Error("GetInt should refuse +Inf")
	}
}

func TestGetIntRejectsFractionalFloat(t *testing.T) {
	d := Dict{"K": 3.14}
	if v, ok := d.GetInt("K"); ok {
		t.Errorf("GetInt should refuse fractional float, got (%d, true)", v)
	}
}

func TestGetIntAcceptsIntegerFloat(t *testing.T) {
	d := Dict{"K": float64(42)}
	v, ok := d.GetInt("K")
	if !ok || v != 42 {
		t.Errorf("GetInt(42.0) = (%d, %v), want (42, true)", v, ok)
	}
}
