package agent

import (
	"context"
	"strings"
)

// Analysis stores decision support artifacts for the next action.
type Analysis struct {
	Summary         string
	RecommendedStep string
	Confidence      float64
}

// Reasoner evaluates current state and plan progress.
type Reasoner struct{}

func NewReasoner() *Reasoner { return &Reasoner{} }

func (r *Reasoner) Reason(_ context.Context, state State, plan AttackPlan) (Analysis, error) {
	if len(plan.Stages) == 0 {
		return Analysis{Summary: "No stages available", RecommendedStep: "stop", Confidence: 0.0}, nil
	}
	lastOutcome := ""
	if len(state.Actions) > 0 {
		lastOutcome = strings.ToLower(state.Actions[len(state.Actions)-1].Outcome)
	}
	if strings.Contains(lastOutcome, "blocked") {
		return Analysis{Summary: "Previous action blocked", RecommendedStep: "adjust_strategy", Confidence: 0.45}, nil
	}
	return Analysis{Summary: "Progressing through campaign workflow", RecommendedStep: plan.Stages[0].Name, Confidence: 0.8}, nil
}
