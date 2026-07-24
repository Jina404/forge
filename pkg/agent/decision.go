package agent

// DecisionEngine chooses the next operation based on plan and analysis.
type DecisionEngine struct{}

func NewDecisionEngine() *DecisionEngine { return &DecisionEngine{} }

func (d *DecisionEngine) SelectAction(plan AttackPlan, analysis Analysis) Action {
	name := analysis.RecommendedStep
	if name == "" && len(plan.Stages) > 0 {
		name = plan.Stages[0].Name
	}
	return Action{
		Name:       name,
		Reason:     analysis.Summary,
		Outcome:    "scheduled",
		Confidence: analysis.Confidence,
	}
}
